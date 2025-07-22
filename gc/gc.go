// Package gc provides garbage collection for go-ipfs.
package gc

import (
	"context"
	"errors"
	"fmt"
	"strings"

	bloom "github.com/ipfs/bbloom"
	bserv "github.com/ipfs/boxo/blockservice"
	bstore "github.com/ipfs/boxo/blockstore"
	offline "github.com/ipfs/boxo/exchange/offline"
	dag "github.com/ipfs/boxo/ipld/merkledag"
	pin "github.com/ipfs/boxo/pinning/pinner"
	"github.com/ipfs/boxo/verifcid"
	cid "github.com/ipfs/go-cid"
	dstore "github.com/ipfs/go-datastore"
	ipld "github.com/ipfs/go-ipld-format"
	logging "github.com/ipfs/go-log"
)

var log = logging.Logger("gc")

// Result represents an incremental output from a garbage collection
// run.  It contains either an error, or the cid of a removed object.
type Result struct {
	KeyRemoved cid.Cid
	Error      error
}

// gc performs a mark and sweep garbage collection of the blocks in the blockstore
// first, it creates a 'marked' set and adds to it the following:
// - all recursively pinned blocks, plus all of their descendants (recursively)
// - bestEffortRoots, plus all of its descendants (recursively)
// - all directly pinned blocks
// - all blocks utilized internally by the pinner
//
// The routine then iterates over every block in the blockstore and
// deletes any block that is not found in the marked set.
func gc(
	ctx context.Context,
	bs bstore.GCBlockstore,
	dstor dstore.Datastore,
	pn pin.Pinner,
	bestEffortRoots []cid.Cid,
	init func(output chan<- Result) error,
	has func(cid.Cid) bool,
) <-chan Result {
	ctx, cancel := context.WithCancel(ctx)

	unlocker := bs.GCLock(ctx)

	output := make(chan Result, 128)

	go func() {
		defer cancel()
		defer close(output)
		defer unlocker.Unlock(ctx)

		if err := init(output); err != nil {
			select {
			case output <- Result{Error: err}:
			case <-ctx.Done():
			}
			return
		}

		keychan, err := bs.AllKeysChan(ctx)
		if err != nil {
			select {
			case output <- Result{Error: err}:
			case <-ctx.Done():
			}
			return
		}

		errors := false
		var removed uint64

	loop:
		for ctx.Err() == nil { // select may not notice that we're "done".
			select {
			case k, ok := <-keychan:
				if !ok {
					break loop
				}
				// NOTE: assumes that all CIDs returned by the keychan are _raw_ CIDv1 CIDs.
				// This means we keep the block as long as we want it somewhere (CIDv1, CIDv0, Raw, other...).
				if !has(k) {
					err := bs.DeleteBlock(ctx, k)
					removed++
					if err != nil {
						errors = true
						select {
						case output <- Result{Error: &CannotDeleteBlockError{k, err}}:
						case <-ctx.Done():
							break loop
						}
						// continue as error is non-fatal
						continue loop
					}
					select {
					case output <- Result{KeyRemoved: k}:
					case <-ctx.Done():
						break loop
					}
				}
			case <-ctx.Done():
				break loop
			}
		}
		if errors {
			select {
			case output <- Result{Error: ErrCannotDeleteSomeBlocks}:
			case <-ctx.Done():
				return
			}
		}

		gds, ok := dstor.(dstore.GCDatastore)
		if !ok {
			return
		}

		err = gds.CollectGarbage(ctx)
		if err != nil {
			select {
			case output <- Result{Error: err}:
			case <-ctx.Done():
			}
			return
		}
	}()

	return output
}

func GC(
	ctx context.Context,
	bs bstore.GCBlockstore,
	dstor dstore.Datastore,
	pn pin.Pinner,
	bestEffortRoots []cid.Cid,
) <-chan Result {
	var gcs *cid.Set

	init := func(output chan<- Result) error {
		bsrv := bserv.New(bs, offline.Exchange(bs))
		ds := dag.NewDAGService(bsrv)

		var err error
		gcs, err = ColoredSet(ctx, pn, ds, bestEffortRoots, output)
		if err != nil {
			return err
		}

		return nil
	}

	has := func(c cid.Cid) bool {
		return gcs.Has(c)
	}

	return gc(ctx, bs, dstor, pn, bestEffortRoots, init, has)
}

func GCBloom(
	ctx context.Context,
	bs bstore.GCBlockstore,
	dstor dstore.Datastore,
	pn pin.Pinner,
	bestEffortRoots []cid.Cid,
	bloomFilterSize int64,
	bloomFilterHashes int,
) <-chan Result {
	var gcs *bloom.Bloom

	init := func(output chan<- Result) error {
		bsrv := bserv.New(bs, offline.Exchange(bs))
		ds := dag.NewDAGService(bsrv)

		var err error
		gcs, err = ColoredSetBloom(
			ctx,
			pn,
			ds,
			bestEffortRoots,
			bloomFilterSize,
			bloomFilterHashes,
			output,
		)
		if err != nil {
			return err
		}

		return nil
	}

	has := func(c cid.Cid) bool {
		return gcs.Has(c.Bytes())
	}

	return gc(ctx, bs, dstor, pn, bestEffortRoots, init, has)
}

// Descendants recursively finds all the descendants of the given roots and
// call the visit function, using the provided dag.GetLinks function
// to walk the tree.
func Descendants(ctx context.Context, getLinks dag.GetLinks, roots <-chan pin.StreamedPin, visit func(cid.Cid) bool) error {
	verifyGetLinks := func(ctx context.Context, c cid.Cid) ([]*ipld.Link, error) {
		err := verifcid.ValidateCid(verifcid.DefaultAllowlist, c)
		if err != nil {
			return nil, err
		}

		return getLinks(ctx, c)
	}

	verboseCidError := func(err error) error {
		if strings.Contains(err.Error(), verifcid.ErrBelowMinimumHashLength.Error()) ||
			strings.Contains(err.Error(), verifcid.ErrPossiblyInsecureHashFunction.Error()) {
			err = fmt.Errorf("\"%s\"\nPlease run 'ipfs pin verify'"+ // nolint
				" to list insecure hashes. If you want to read them,"+
				" please downgrade your go-ipfs to 0.4.13\n", err)
			log.Error(err)
		}
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case wrapper, ok := <-roots:
			if !ok {
				return nil
			}
			if wrapper.Err != nil {
				return wrapper.Err
			}

			// Walk recursively walks the dag and adds the keys to the given set
			err := dag.Walk(ctx, verifyGetLinks, wrapper.Pin.Key, visit, dag.Concurrent())
			if err != nil {
				err = verboseCidError(err)
				return err
			}
		}
	}
}

// toCidV1 converts any CIDv0s to CIDv1s.
func toCidV1(c cid.Cid) cid.Cid {
	if c.Version() == 0 {
		return cid.NewCidV1(c.Type(), c.Hash())
	}
	return c
}

// toRawCid converts any CID to a CID with the raw codec.
func toRawCid(c cid.Cid) cid.Cid {
	return cid.NewCidV1(cid.Raw, c.Hash())
}

// ColoredSet computes the set of nodes in the graph that are pinned by the
// pins in the given pinner.
func coloredSet(
	ctx context.Context,
	pn pin.Pinner,
	ng ipld.NodeGetter,
	bestEffortRoots []cid.Cid,
	visit func(cid.Cid) bool,
	output chan<- Result,
) error {
	errors := false
	getLinks := func(ctx context.Context, cid cid.Cid) ([]*ipld.Link, error) {
		links, err := ipld.GetLinks(ctx, ng, cid)
		if err != nil {
			errors = true
			select {
			case output <- Result{Error: &CannotFetchLinksError{cid, err}}:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return links, nil
	}
	rkeys := pn.RecursiveKeys(ctx, false)
	err := Descendants(ctx, getLinks, rkeys, visit)
	if err != nil {
		errors = true
		select {
		case output <- Result{Error: err}:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	bestEffortGetLinks := func(ctx context.Context, cid cid.Cid) ([]*ipld.Link, error) {
		links, err := ipld.GetLinks(ctx, ng, cid)
		if err != nil && !ipld.IsNotFound(err) {
			errors = true
			select {
			case output <- Result{Error: &CannotFetchLinksError{cid, err}}:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return links, nil
	}
	bestEffortRootsChan := make(chan pin.StreamedPin)
	go func() {
		defer close(bestEffortRootsChan)
		for _, root := range bestEffortRoots {
			select {
			case <-ctx.Done():
				return
			case bestEffortRootsChan <- pin.StreamedPin{Pin: pin.Pinned{Key: root}}:
			}
		}
	}()
	err = Descendants(ctx, bestEffortGetLinks, bestEffortRootsChan, visit)
	if err != nil {
		errors = true
		select {
		case output <- Result{Error: err}:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	dkeys := pn.DirectKeys(ctx, false)
	for k := range dkeys {
		if k.Err != nil {
			return k.Err
		}
		visit(toCidV1(k.Pin.Key))
	}

	ikeys := pn.InternalPins(ctx, false)
	err = Descendants(ctx, getLinks, ikeys, visit)
	if err != nil {
		errors = true
		select {
		case output <- Result{Error: err}:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	if errors {
		return ErrCannotFetchAllLinks
	}

	return nil
}

func ColoredSet(
	ctx context.Context,
	pn pin.Pinner,
	ng ipld.NodeGetter,
	bestEffortRoots []cid.Cid,
	output chan<- Result,
) (*cid.Set, error) {
	gcs := cid.NewSet()
	visit := func(c cid.Cid) bool {
		return gcs.Visit(toRawCid(c))
	}
	if err := coloredSet(ctx, pn, ng, bestEffortRoots, visit, output); err != nil {
		return nil, err
	}
	return gcs, nil
}

func ColoredSetBloom(
	ctx context.Context,
	pn pin.Pinner,
	ng ipld.NodeGetter,
	bestEffortRoots []cid.Cid,
	bloomFilterSize int64,
	bloomFilterHashes int,
	output chan<- Result,
) (*bloom.Bloom, error) {
	gcs, err := bloom.New(float64(bloomFilterSize), float64(bloomFilterHashes))
	if err != nil {
		return nil, err
	}
	visit := func(c cid.Cid) bool {
		gcs.Add(toRawCid(c).Bytes())
		return true
	}
	if err := coloredSet(ctx, pn, ng, bestEffortRoots, visit, output); err != nil {
		return nil, err
	}
	return gcs, nil
}

// ErrCannotFetchAllLinks is returned as the last Result in the GC output
// channel when there was an error creating the marked set because of a
// problem when finding descendants.
var ErrCannotFetchAllLinks = errors.New("garbage collection aborted: could not retrieve some links")

// ErrCannotDeleteSomeBlocks is returned when removing blocks marked for
// deletion fails as the last Result in GC output channel.
var ErrCannotDeleteSomeBlocks = errors.New("garbage collection incomplete: could not delete some blocks")

// CannotFetchLinksError provides detailed information about which links
// could not be fetched and can appear as a Result in the GC output channel.
type CannotFetchLinksError struct {
	Key cid.Cid
	Err error
}

// Error implements the error interface for this type with a useful
// message.
func (e *CannotFetchLinksError) Error() string {
	return fmt.Sprintf("could not retrieve links for %s: %s", e.Key, e.Err)
}

// CannotDeleteBlockError provides detailed information about which
// blocks could not be deleted and can appear as a Result in the GC output
// channel.
type CannotDeleteBlockError struct {
	Key cid.Cid
	Err error
}

// Error implements the error interface for this type with a
// useful message.
func (e *CannotDeleteBlockError) Error() string {
	return fmt.Sprintf("could not remove %s: %s", e.Key, e.Err)
}

package node

import (
	"testing"
	"time"

	"github.com/ipfs/kubo/config"
)

func TestBitswapRateLimitValues(t *testing.T) {
	cfg := &config.Config{}

	upload, download := bitswapRateLimitValues(cfg)
	if upload != 0 || download != 0 {
		t.Fatalf("default limits = (%d, %d), want (0, 0)", upload, download)
	}

	cfg.Internal.Bitswap = &config.InternalBitswap{
		MaxUploadBytesPerSec:   config.NewOptionalInteger(1024),
		MaxDownloadBytesPerSec: config.NewOptionalInteger(2048),
	}

	upload, download = bitswapRateLimitValues(cfg)
	if upload != 1024 || download != 2048 {
		t.Fatalf("configured limits = (%d, %d), want (1024, 2048)", upload, download)
	}
}

func TestBitswapOptionsRebroadcastDelayValue(t *testing.T) {
	cfg := &config.Config{}
	out := BitswapOptions(cfg).(func() bitswapOptionsOut)()
	if len(out.BitswapOpts) == 0 {
		t.Fatal("BitswapOpts is empty")
	}

	cfg.Internal.Bitswap = &config.InternalBitswap{
		RebroadcastDelay: *config.NewOptionalDuration(876000 * time.Hour),
	}
	out = BitswapOptions(cfg).(func() bitswapOptionsOut)()
	if len(out.BitswapOpts) == 0 {
		t.Fatal("BitswapOpts is empty")
	}
}

func TestBitswapDontHaveTimeoutConfig(t *testing.T) {
	cfg := config.InternalBitswap{
		DontHaveTimeout: &config.BitswapDontHaveTimeout{
			DontHaveTimeout:            *config.NewOptionalDuration(20 * time.Second),
			MaxExpectedWantProcessTime: *config.NewOptionalDuration(5 * time.Second),
			MaxTimeout:                 *config.NewOptionalDuration(30 * time.Second),
			MinTimeout:                 *config.NewOptionalDuration(time.Second),
		},
	}

	got := bitswapDontHaveTimeoutConfig(cfg)
	if got == nil {
		t.Fatal("bitswapDontHaveTimeoutConfig returned nil")
	}
	if got.DontHaveTimeout != 20*time.Second {
		t.Fatalf("DontHaveTimeout = %s, want 20s", got.DontHaveTimeout)
	}
	if got.MaxExpectedWantProcessTime != 5*time.Second {
		t.Fatalf("MaxExpectedWantProcessTime = %s, want 5s", got.MaxExpectedWantProcessTime)
	}
	if got.MaxTimeout != 30*time.Second {
		t.Fatalf("MaxTimeout = %s, want 30s", got.MaxTimeout)
	}
	if got.MinTimeout != time.Second {
		t.Fatalf("MinTimeout = %s, want 1s", got.MinTimeout)
	}
}

func TestBitswapDontHaveTimeoutConfigKeepsBoxoDefaultWhenUnset(t *testing.T) {
	cfg := config.InternalBitswap{}
	if got := bitswapDontHaveTimeoutConfig(cfg); got != nil {
		t.Fatal("unset DontHaveTimeout config should keep Boxo default by returning nil")
	}
}

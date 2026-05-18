package node

import (
	"testing"

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

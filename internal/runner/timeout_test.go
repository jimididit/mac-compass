package runner

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jimididit/mac-compass/internal/catalog"
)

func TestEffectiveTimeout(t *testing.T) {
	opts := Options{Timeout: 90 * time.Second}
	if got := effectiveTimeout(catalog.Check{}, opts); got != 90*time.Second {
		t.Errorf("no per-check cap: %v", got)
	}
	if got := effectiveTimeout(catalog.Check{Timeout: 20 * time.Second}, opts); got != 20*time.Second {
		t.Errorf("a shorter per-check cap wins: %v", got)
	}
	if got := effectiveTimeout(catalog.Check{Timeout: 5 * time.Minute}, opts); got != 90*time.Second {
		t.Errorf("a per-check cap never extends the global timeout: %v", got)
	}
}

func TestRun_PerCheckTimeoutApplies(t *testing.T) {
	skipNonUnix(t)
	ch := catalog.Check{Section: "test", Name: "slow", Script: "sleep 30", Timeout: 300 * time.Millisecond}
	opts := DefaultOptions()
	opts.Timeout = 30 * time.Second
	start := time.Now()
	res := Run(context.Background(), ch, opts, nil, nil)
	if res.Err == nil || !strings.Contains(res.Err.Error(), "timeout after 300ms") {
		t.Fatalf("want the per-check timeout; got %v", res.Err)
	}
	if time.Since(start) > 10*time.Second {
		t.Error("the check should have been stopped at its own cap")
	}
}

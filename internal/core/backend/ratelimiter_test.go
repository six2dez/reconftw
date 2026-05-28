// SPDX-License-Identifier: MIT
//
// Tests 9-12 from .planning/phases/03-foundation-kernel/03-04-PLAN.md Task 2
// (RateLimiter using golang.org/x/time/rate).
package backend_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/six2dez/reconftw/internal/core/backend"
)

// Test 9: NewRateLimiter with per-tool RPS — Wait blocks until token is issued.
// Validates that a burst of 3 calls on a 2 RPS limiter takes >= ~500ms total
// (second call uses the initial burst token; the third must wait for refill).
func TestRateLimiter_PerTool_WaitBlocksUntilToken(t *testing.T) {
	limiter := backend.NewRateLimiter(map[string]int{"httpx": 2}, 0)
	ctx := context.Background()

	// Drain initial burst — at rate 2 with burst 2, first two calls return ~instantly.
	start := time.Now()
	_ = limiter.Wait(ctx, "httpx")
	_ = limiter.Wait(ctx, "httpx")
	burstElapsed := time.Since(start)
	if burstElapsed > 100*time.Millisecond {
		t.Errorf("first two waits took %v, want < 100ms (initial burst)", burstElapsed)
	}

	// Third wait must block for ~500ms (1/RPS = 500ms refill).
	thirdStart := time.Now()
	_ = limiter.Wait(ctx, "httpx")
	thirdElapsed := time.Since(thirdStart)
	if thirdElapsed < 400*time.Millisecond {
		t.Errorf("third wait took %v, want >= 400ms (1/2 RPS refill window)", thirdElapsed)
	}
}

// Test 10: Wait on an unknown tool returns immediately (nil rate.Limiter case → unlimited).
func TestRateLimiter_UnknownTool_NoLimitReturnsImmediately(t *testing.T) {
	limiter := backend.NewRateLimiter(map[string]int{"httpx": 1}, 0)
	ctx := context.Background()

	start := time.Now()
	if err := limiter.Wait(ctx, "this-tool-not-configured"); err != nil {
		t.Fatalf("Wait(unconfigured-tool) returned err=%v", err)
	}
	if elapsed := time.Since(start); elapsed > 50*time.Millisecond {
		t.Errorf("Wait(unconfigured-tool) took %v, want ~0 (no limit set)", elapsed)
	}
}

// Test 11: Both global limit and per-tool limit apply — the more restrictive
// dictates wait time.
func TestRateLimiter_GlobalAndPerToolCombined_MoreRestrictiveWins(t *testing.T) {
	// Per-tool: 10 RPS (loose). Global: 2 RPS (tight). Global should dominate.
	limiter := backend.NewRateLimiter(map[string]int{"httpx": 10}, 2)
	ctx := context.Background()

	// Drain burst.
	_ = limiter.Wait(ctx, "httpx")
	_ = limiter.Wait(ctx, "httpx")

	thirdStart := time.Now()
	_ = limiter.Wait(ctx, "httpx")
	if thirdElapsed := time.Since(thirdStart); thirdElapsed < 400*time.Millisecond {
		t.Errorf("third wait took %v, want >= 400ms (global 2 RPS dominates over per-tool 10 RPS)", thirdElapsed)
	}
}

// Test 12: Concurrent waits from multiple goroutines are race-clean under -race.
func TestRateLimiter_ConcurrentWaits_RaceClean(t *testing.T) {
	limiter := backend.NewRateLimiter(map[string]int{"httpx": 1000}, 0)
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				if err := limiter.Wait(ctx, "httpx"); err != nil {
					t.Errorf("Wait returned err=%v", err)
				}
			}
		}()
	}
	wg.Wait()
}

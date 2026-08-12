// SPDX-License-Identifier: MIT
//
// INTEG-05 — the central rate limiter must actually throttle.
//
// pickLimiter previously returned backend.NewRateLimiter(map[string]int{}, 0),
// a no-op that let every Wait return immediately, so the configured
// *_RATELIMIT / adaptive-rate settings were never enforced centrally. These
// tests prove the fix two ways:
//
//  1. Deterministic (no wall-clock): buildLimiterConfig derives the per-tool
//     map + global cap from config — httpx/nuclei/dnsx present at their
//     configured RPS on Defaults(); zero-rate tools omitted; global only when
//     adaptive_rate.enabled; nil/zero-value config is safe.
//  2. Behavioral (coarse timing, per ratelimiter_test.go style): a
//     pickLimiter-built limiter throttles a configured tool through the real
//     backend.Runner exec path, while an unlisted tool passes straight
//     through. Build/vet alone would pass even with the old no-op limiter, so
//     this behavioral proof is the one that catches a regression.
//
// This is an internal (package appctx) test so it can assert buildLimiterConfig
// and pickLimiter directly — RateLimiter's per-tool/global maps are unexported,
// so a deterministic assertion needs the derived (map, int) rather than
// reflection on a constructed limiter.
package appctx

import (
	"context"
	"testing"
	"time"

	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
)

// Task 1 — buildLimiterConfig on Defaults() populates the per-tool map from the
// configured *_RATELIMIT values and omits zero-rate tools.
func TestBuildLimiterConfig_DefaultsPopulatePerToolMap(t *testing.T) {
	perTool, global := buildLimiterConfig(config.Defaults())

	// Defaults: httpx 150, nuclei 150, dnsx 500 → present at those RPS.
	wantPresent := map[string]int{"httpx": 150, "nuclei": 150, "dnsx": 500}
	for name, want := range wantPresent {
		got, ok := perTool[name]
		if !ok {
			t.Errorf("perTool[%q] missing; want %d (INTEG-05: map must be built from config)", name, want)
			continue
		}
		if got != want {
			t.Errorf("perTool[%q] = %d, want %d (configured RateLimit)", name, got, want)
		}
	}

	// Defaults: ffuf 0, favirecon 0 → omitted (0 == unlimited, not throttled).
	for _, name := range []string{"ffuf", "favirecon"} {
		if rps, ok := perTool[name]; ok {
			t.Errorf("perTool[%q] = %d present; want omitted (RateLimit 0 == unlimited)", name, rps)
		}
	}

	// Defaults: AdaptiveRate disabled → no global cap.
	if global != 0 {
		t.Errorf("global = %d, want 0 (adaptive_rate disabled by default → no global cap)", global)
	}
}

// Task 1 — a tool whose RateLimit is 0 is omitted (unlimited); a positive rate
// is inserted.
func TestBuildLimiterConfig_ZeroRateOmittedPositiveInserted(t *testing.T) {
	cfg := config.Defaults()
	cfg.Web.Probe.RateLimit = 0 // httpx → unlimited
	cfg.Web.Fuzz.RateLimit = 42 // ffuf  → throttled

	perTool, _ := buildLimiterConfig(cfg)

	if _, ok := perTool["httpx"]; ok {
		t.Errorf("perTool[httpx] present; want omitted when RateLimit == 0")
	}
	if got := perTool["ffuf"]; got != 42 {
		t.Errorf("perTool[ffuf] = %d, want 42 (positive RateLimit inserted)", got)
	}
}

// Task 1 — the global cap comes from adaptive_rate.max_rate only when
// adaptive_rate.enabled is true.
func TestBuildLimiterConfig_GlobalFromAdaptiveRate(t *testing.T) {
	cfg := config.Defaults()

	cfg.AdaptiveRate.Enabled = true
	cfg.AdaptiveRate.MaxRate = 100
	if _, global := buildLimiterConfig(cfg); global != 100 {
		t.Errorf("global = %d, want 100 (adaptive_rate.enabled → MaxRate)", global)
	}

	cfg.AdaptiveRate.Enabled = false
	if _, global := buildLimiterConfig(cfg); global != 0 {
		t.Errorf("global = %d, want 0 (adaptive_rate.disabled → no global cap)", global)
	}
}

// Task 1 — nil-safe and zero-value-safe: no panic, non-nil limiter, empty map.
func TestPickLimiter_NilAndZeroValueSafe(t *testing.T) {
	if perTool, global := buildLimiterConfig(nil); len(perTool) != 0 || global != 0 {
		t.Errorf("buildLimiterConfig(nil) = (%v, %d), want (empty, 0)", perTool, global)
	}
	if lim := pickLimiter(nil); lim == nil {
		t.Fatal("pickLimiter(nil) = nil, want non-nil (nil-safe no-op limiter)")
	}

	// Zero-value config: all rates 0, adaptive disabled → empty limiter, no panic.
	perTool, global := buildLimiterConfig(&config.Config{})
	if len(perTool) != 0 || global != 0 {
		t.Errorf("buildLimiterConfig(zero-value) = (%v, %d), want (empty, 0)", perTool, global)
	}
	if lim := pickLimiter(&config.Config{}); lim == nil {
		t.Fatal("pickLimiter(zero-value) = nil, want non-nil")
	}
}

// Task 2 — behavioral proof: a pickLimiter-built limiter throttles a configured
// tool through the real backend.Runner exec path, while an unlisted tool passes
// straight through. Coarse timing (rps=2 → the 3rd call blocks ~500ms) mirrors
// ratelimiter_test.go to avoid CI flakiness. The old no-op limiter would let the
// 3rd call return in ~exec time, so this test fails against the regression.
func TestPickLimiter_ThrottlesConfiguredToolThroughRunner(t *testing.T) {
	// Config: only httpx capped (2 RPS); everything else unlimited; no global.
	cfg := config.Defaults()
	cfg.Web.Probe.RateLimit = 2                 // httpx → 2 RPS
	cfg.Web.Nuclei.RateLimit = 0                // omit
	cfg.Subdomains.DNSResolve.DNSXRateLimit = 0 // omit → unlisted passthrough
	cfg.AdaptiveRate.Enabled = false            // no global cap

	limiter := pickLimiter(cfg)

	// Registry mirrors runner_test.go: register the tool names as harmless
	// /bin/echo invocations so Runner.Run exercises Limiter.Wait(ctx, name).
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "httpx", Path: "/bin/echo"})
	reg.Register(&backend.Tool{Name: "dnsx", Path: "/bin/echo"}) // registered but unlisted (RPS 0)
	r := backend.NewRunner(backend.NewLocalBackend(0), reg, limiter)
	ctx := context.Background()

	// Drain the initial burst (rate 2, burst 2): first two Run calls are fast.
	burstStart := time.Now()
	if _, err := r.Run(ctx, "httpx", nil); err != nil {
		t.Fatalf("Run(httpx) #1 err=%v", err)
	}
	if _, err := r.Run(ctx, "httpx", nil); err != nil {
		t.Fatalf("Run(httpx) #2 err=%v", err)
	}
	if burst := time.Since(burstStart); burst > 300*time.Millisecond {
		t.Errorf("burst of 2 Run(httpx) took %v, want < 300ms (initial burst tokens)", burst)
	}

	// Third Run must block ~500ms (1/2 RPS refill) — the throttle taking effect.
	thirdStart := time.Now()
	if _, err := r.Run(ctx, "httpx", nil); err != nil {
		t.Fatalf("Run(httpx) #3 err=%v", err)
	}
	if third := time.Since(thirdStart); third < 400*time.Millisecond {
		t.Errorf("3rd Run(httpx) took %v, want >= 400ms (limiter throttling; no-op would be ~instant)", third)
	}

	// Unlisted tool (dnsx: registered, RateLimit 0, no global) passes straight
	// through even across several calls — no accidental throttle.
	passStart := time.Now()
	for i := 0; i < 5; i++ {
		if _, err := r.Run(ctx, "dnsx", nil); err != nil {
			t.Fatalf("Run(dnsx) #%d err=%v", i+1, err)
		}
	}
	if pass := time.Since(passStart); pass > 300*time.Millisecond {
		t.Errorf("5x Run(dnsx unlisted) took %v, want < 300ms (unlimited, no throttle)", pass)
	}
}

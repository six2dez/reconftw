// SPDX-License-Identifier: MIT
//
// RateLimiter — FOUND-07 per-tool + global rate limiting using golang.org/x/time/rate.
//
// Pattern: each per-tool entry gets its own *rate.Limiter; an optional global limiter
// caps the aggregate. Wait blocks until both layers issue a token. A nil per-tool
// limiter (i.e. tool not configured) means "no per-tool limit" — Wait returns the
// global token decision only.
//
// Rationale for using golang.org/x/time/rate (RESEARCH.md §Stack Snapshot):
//   - Token-bucket primitive proven across the Go ecosystem
//   - ctx-aware Wait() returns on ctx cancellation
//   - Burst size = RPS in our config maps directly to "max burst before throttling"
//
// FOUND-07 spec: "RateLimiter supporting per-tool, per-target, and global caps".
// Per-target capping is deferred to Plan 05 (Scheduler) where the per-target key
// is available; Plan 04 ships per-tool + global, sufficient for Phase 4 wiring.
package backend

import (
	"context"
	"sync"

	"golang.org/x/time/rate"
)

// RateLimiter caps concurrent tool invocations by per-tool and global RPS.
type RateLimiter struct {
	mu      sync.RWMutex
	perTool map[string]*rate.Limiter
	global  *rate.Limiter
}

// NewRateLimiter constructs a RateLimiter. perToolRPS maps tool-name → requests-
// per-second (0 or unset means no per-tool limit). globalRPS sets the aggregate
// cap across all tools (0 means no global limit).
//
// Burst size matches RPS for each limiter so a brief burst-of-RPS is permitted
// before throttling kicks in.
func NewRateLimiter(perToolRPS map[string]int, globalRPS int) *RateLimiter {
	rl := &RateLimiter{
		perTool: make(map[string]*rate.Limiter, len(perToolRPS)),
	}
	for name, rps := range perToolRPS {
		if rps > 0 {
			rl.perTool[name] = rate.NewLimiter(rate.Limit(rps), rps)
		}
	}
	if globalRPS > 0 {
		rl.global = rate.NewLimiter(rate.Limit(globalRPS), globalRPS)
	}
	return rl
}

// Wait blocks until both the per-tool (if configured) and global (if configured)
// rate limiters issue tokens. Returns immediately if no limits apply to the tool.
// Returns ctx.Err() if ctx is cancelled while waiting.
func (rl *RateLimiter) Wait(ctx context.Context, tool string) error {
	rl.mu.RLock()
	toolLim := rl.perTool[tool]
	global := rl.global
	rl.mu.RUnlock()

	if toolLim != nil {
		if err := toolLim.Wait(ctx); err != nil {
			return err
		}
	}
	if global != nil {
		if err := global.Wait(ctx); err != nil {
			return err
		}
	}
	return nil
}

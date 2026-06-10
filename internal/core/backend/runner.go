// SPDX-License-Identifier: MIT
//
// Runner — wraps Backend + ToolRegistry + RateLimiter so Tasks call a single shape
// (`app.Tools.Run(ctx, name, args)`) regardless of which Backend is configured.
//
// Per ADR §5.3 line 1727: `AppContext.Tools *backend.Runner`. The Runner is the
// FOUND-10-aligned single allowed call site for tool invocation — Phase 4+ Tasks
// never touch Backend directly.
//
// Dispatch order on Run / Stream:
//
//  1. Registry.Lookup(name)   → *ToolError{ExitCode: -1} if not registered
//  2. Limiter.Wait(ctx, name) → wrapped in *ToolError if interrupted
//  3. Backend.Exec / Stream
//
// Phase 5 may add: per-target rate limit, dry-run mode, circuit breaker.
package backend

import (
	stderrors "errors"
	"context"

	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
)

// Runner orchestrates backend dispatch through registry + rate limiter.
type Runner struct {
	Backend  Backend
	Registry *ToolRegistry
	Limiter  *RateLimiter
}

// NewRunner constructs a Runner. All three dependencies may be nil-ish:
//   - backend  must be non-nil (panics on Run/Stream if nil)
//   - registry must be non-nil
//   - limiter  may be nil (no rate-limit gate)
func NewRunner(b Backend, reg *ToolRegistry, lim *RateLimiter) *Runner {
	return &Runner{Backend: b, Registry: reg, Limiter: lim}
}

// Run looks up toolName, waits on the rate limiter, then dispatches to
// Backend.Exec. Returns *ToolError{ExitCode:-1, Inner: "tool not registered"}
// if the tool is unknown.
func (r *Runner) Run(ctx context.Context, toolName string, args []string) (*Result, error) {
	tool, ok := r.Registry.Lookup(toolName)
	if !ok {
		return nil, &coreerrors.ToolError{
			Tool:     toolName,
			ExitCode: -1,
			Inner:    stderrors.New("tool not registered"),
		}
	}
	if r.Limiter != nil {
		if err := r.Limiter.Wait(ctx, toolName); err != nil {
			return nil, &coreerrors.ToolError{
				Tool:     toolName,
				ExitCode: -1,
				Inner:    err,
			}
		}
	}
	return r.Backend.Exec(ctx, tool, args)
}

// RunEnv is Run with additional "KEY=VALUE" child-env entries forwarded to
// Backend.ExecEnv. Use this to pass a secret (e.g. GH_TOKEN) into a tool's child
// environment WITHOUT placing it on argv (ARCH-02). The env entries are appended
// onto the os.Environ() baseline by LocalBackend; an empty env is byte-for-byte
// equivalent to Run. Same unregistered-tool / rate-limit error contract as Run.
func (r *Runner) RunEnv(ctx context.Context, toolName string, args []string, env []string) (*Result, error) {
	tool, ok := r.Registry.Lookup(toolName)
	if !ok {
		return nil, &coreerrors.ToolError{
			Tool:     toolName,
			ExitCode: -1,
			Inner:    stderrors.New("tool not registered"),
		}
	}
	if r.Limiter != nil {
		if err := r.Limiter.Wait(ctx, toolName); err != nil {
			return nil, &coreerrors.ToolError{
				Tool:     toolName,
				ExitCode: -1,
				Inner:    err,
			}
		}
	}
	return r.Backend.ExecEnv(ctx, tool, args, env)
}

// Stream looks up toolName, waits on the rate limiter, then dispatches to
// Backend.Stream. Same error contract as Run for the unregistered-tool case.
func (r *Runner) Stream(ctx context.Context, toolName string, args []string) (<-chan Event, error) {
	tool, ok := r.Registry.Lookup(toolName)
	if !ok {
		return nil, &coreerrors.ToolError{
			Tool:     toolName,
			ExitCode: -1,
			Inner:    stderrors.New("tool not registered"),
		}
	}
	if r.Limiter != nil {
		if err := r.Limiter.Wait(ctx, toolName); err != nil {
			return nil, &coreerrors.ToolError{
				Tool:     toolName,
				ExitCode: -1,
				Inner:    err,
			}
		}
	}
	return r.Backend.Stream(ctx, tool, args)
}

// StreamEnv is Stream with additional "KEY=VALUE" child-env entries forwarded to
// Backend.StreamEnv (see RunEnv for the env contract).
func (r *Runner) StreamEnv(ctx context.Context, toolName string, args []string, env []string) (<-chan Event, error) {
	tool, ok := r.Registry.Lookup(toolName)
	if !ok {
		return nil, &coreerrors.ToolError{
			Tool:     toolName,
			ExitCode: -1,
			Inner:    stderrors.New("tool not registered"),
		}
	}
	if r.Limiter != nil {
		if err := r.Limiter.Wait(ctx, toolName); err != nil {
			return nil, &coreerrors.ToolError{
				Tool:     toolName,
				ExitCode: -1,
				Inner:    err,
			}
		}
	}
	return r.Backend.StreamEnv(ctx, tool, args, env)
}

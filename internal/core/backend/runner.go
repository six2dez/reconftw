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
	"context"
	stderrors "errors"

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

// applyToolContract prepends Tool.DefaultArgs to args and derives a
// Tool.Timeout-bounded context.
//
// Both fields are loaded from tools.lock and were carried on every Tool while
// no code path applied them: default_args never reached a command line, and
// timeout_seconds bounded nothing on the local backend, so a hung tool ran
// until the whole scan's context expired. The returned cancel is always
// non-nil and must be called by the caller.
func applyToolContract(ctx context.Context, t *Tool, args []string) (context.Context, context.CancelFunc, []string) {
	if len(t.DefaultArgs) > 0 {
		// DefaultArgs first so a caller-supplied flag of the same name wins on
		// tools that take last-one-wins semantics.
		merged := make([]string, 0, len(t.DefaultArgs)+len(args))
		merged = append(merged, t.DefaultArgs...)
		args = append(merged, args...)
	}
	if t.Timeout > 0 {
		c, cancel := context.WithTimeout(ctx, t.Timeout)
		return c, cancel, args
	}
	return ctx, func() {}, args
}

// Run looks up toolName, waits on the rate limiter, then dispatches to
// Backend.Exec. Returns *ToolError{ExitCode:-1, Inner: "tool not registered"}
// if the tool is unknown.
//
// Tool.DefaultArgs and Tool.Timeout from tools.lock are applied here — the
// Runner is the single seam every tool invocation passes through, so honouring
// the manifest in one place covers every caller.
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
	ctx, cancel, args := applyToolContract(ctx, tool, args)
	defer cancel()
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
	ctx, cancel, args := applyToolContract(ctx, tool, args)
	defer cancel()
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
	return r.streamWithContract(ctx, tool, args, func(c context.Context, a []string) (<-chan Event, error) {
		return r.Backend.Stream(c, tool, a)
	})
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
	return r.streamWithContract(ctx, tool, args, func(c context.Context, a []string) (<-chan Event, error) {
		return r.Backend.StreamEnv(c, tool, a, env)
	})
}

// streamWithContract applies the tools.lock contract to a streaming call.
//
// A stream keeps running after the call returns, so the Tool.Timeout context
// cannot be released with a plain defer — that would cancel the command the
// instant it started. Instead the cancel is deferred onto a relay goroutine
// that lives exactly as long as the event channel, so the timeout bounds the
// whole stream and the context is released as soon as it closes.
func (r *Runner) streamWithContract(
	ctx context.Context,
	tool *Tool,
	args []string,
	dispatch func(context.Context, []string) (<-chan Event, error),
) (<-chan Event, error) {
	ctx, cancel, args := applyToolContract(ctx, tool, args)
	src, err := dispatch(ctx, args)
	if err != nil {
		cancel()
		return nil, err
	}
	out := make(chan Event, 64)
	go func() {
		defer cancel()
		defer close(out)
		// CONTRACT-PRESERVING RELAY: `ev` is forwarded wholesale and never
		// rewritten, so Event.Err — the terminal error the Drain/Collect helpers
		// exist to surface — reaches the consumer unmodified. Any future change
		// that reconstructs the Event field-by-field, filters on ev.Err, or drops
		// events on a non-cancellation path silently re-breaks audit finding F6:
		// a tool that exits non-zero would once again look identical to one that
		// finished cleanly.
		for ev := range src {
			select {
			case out <- ev:
			case <-ctx.Done():
				// The consumer abandoned the channel. A bare `out <- ev` would
				// block this goroutine forever, holding the Tool.Timeout context
				// open and leaking both the relay and the child process it
				// bounds. Drain the source so the producer can finish, then stop.
				for range src { //nolint:revive // intentional drain
				}
				return
			}
		}
	}()
	return out, nil
}

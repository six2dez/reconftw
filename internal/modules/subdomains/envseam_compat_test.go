// envseam_compat_test.go — env-seam compile guards for the package's mock
// Backends (Phase 07-09 GAP-02). The Backend interface gained additive
// ExecEnv/StreamEnv methods; these subdomains tests never exercise child-env
// injection, so each mock delegates the env-capable variant to its existing
// nil-env Exec/Stream. Keeping these in one file avoids scattering identical
// boilerplate across the per-Task test files.
package subdomains_test

import (
	"context"

	"github.com/six2dez/reconftw/internal/core/backend"
)

func (m *permutStreamBackend) ExecEnv(ctx context.Context, t *backend.Tool, args []string, _ []string) (*backend.Result, error) {
	return m.Exec(ctx, t, args)
}

func (m *permutStreamBackend) StreamEnv(ctx context.Context, t *backend.Tool, args []string, _ []string) (<-chan backend.Event, error) {
	return m.Stream(ctx, t, args)
}

func (t *trackingBackend) ExecEnv(ctx context.Context, tool *backend.Tool, args []string, _ []string) (*backend.Result, error) {
	return t.Exec(ctx, tool, args)
}

func (t *trackingBackend) StreamEnv(ctx context.Context, tool *backend.Tool, args []string, _ []string) (<-chan backend.Event, error) {
	return t.Stream(ctx, tool, args)
}

func (m *mockStreamBackend) ExecEnv(ctx context.Context, t *backend.Tool, args []string, _ []string) (*backend.Result, error) {
	return m.Exec(ctx, t, args)
}

func (m *mockStreamBackend) StreamEnv(ctx context.Context, t *backend.Tool, args []string, _ []string) (<-chan backend.Event, error) {
	return m.Stream(ctx, t, args)
}

func (m *streamTrackingBackend) ExecEnv(ctx context.Context, t *backend.Tool, args []string, _ []string) (*backend.Result, error) {
	return m.Exec(ctx, t, args)
}

func (m *streamTrackingBackend) StreamEnv(ctx context.Context, t *backend.Tool, args []string, _ []string) (<-chan backend.Event, error) {
	return m.Stream(ctx, t, args)
}

func (m *mockBackend) ExecEnv(ctx context.Context, t *backend.Tool, args []string, _ []string) (*backend.Result, error) {
	return m.Exec(ctx, t, args)
}

func (m *mockBackend) StreamEnv(ctx context.Context, t *backend.Tool, args []string, _ []string) (<-chan backend.Event, error) {
	return m.Stream(ctx, t, args)
}

func (m *mockMultiToolBackend) ExecEnv(ctx context.Context, tool *backend.Tool, args []string, _ []string) (*backend.Result, error) {
	return m.Exec(ctx, tool, args)
}

func (m *mockMultiToolBackend) StreamEnv(ctx context.Context, tool *backend.Tool, args []string, _ []string) (<-chan backend.Event, error) {
	return m.Stream(ctx, tool, args)
}

func (t *toolCallTracker) ExecEnv(ctx context.Context, tool *backend.Tool, args []string, _ []string) (*backend.Result, error) {
	return t.Exec(ctx, tool, args)
}

func (t *toolCallTracker) StreamEnv(ctx context.Context, tool *backend.Tool, args []string, _ []string) (<-chan backend.Event, error) {
	return t.Stream(ctx, tool, args)
}

// ExecOpts satisfies the backend.Backend options seam added in 18-01. It
// PRESERVES this fake's pre-18-01 dispatch exactly: Runner.Run used to call
// Backend.Exec and Runner.RunEnv used to call Backend.ExecEnv, and both now
// arrive here, so the env-set case forwards to ExecEnv and the zero case to Exec.
//
// It deliberately IGNORES opts.Stdin, opts.StdinPath and opts.Dir: this fake
// never receives them. A fake that needs to ASSERT on stdin must write its own
// ExecOpts instead of inheriting this forward — silently discarding the bytes is
// correct only because nothing here is testing them.
func (m *permutStreamBackend) ExecOpts(ctx context.Context, t *backend.Tool, args []string, opts backend.ExecOptions) (*backend.Result, error) {
	if len(opts.Env) > 0 {
		return m.ExecEnv(ctx, t, args, opts.Env)
	}
	return m.Exec(ctx, t, args)
}

// StreamOpts satisfies the backend.Backend options seam (see ExecOpts).
func (m *permutStreamBackend) StreamOpts(ctx context.Context, t *backend.Tool, args []string, opts backend.ExecOptions) (<-chan backend.Event, error) {
	if len(opts.Env) > 0 {
		return m.StreamEnv(ctx, t, args, opts.Env)
	}
	return m.Stream(ctx, t, args)
}

// ExecOpts satisfies the backend.Backend options seam added in 18-01. It
// PRESERVES this fake's pre-18-01 dispatch exactly: Runner.Run used to call
// Backend.Exec and Runner.RunEnv used to call Backend.ExecEnv, and both now
// arrive here, so the env-set case forwards to ExecEnv and the zero case to Exec.
//
// It deliberately IGNORES opts.Stdin, opts.StdinPath and opts.Dir: this fake
// never receives them. A fake that needs to ASSERT on stdin must write its own
// ExecOpts instead of inheriting this forward — silently discarding the bytes is
// correct only because nothing here is testing them.
func (t *trackingBackend) ExecOpts(ctx context.Context, tool *backend.Tool, args []string, opts backend.ExecOptions) (*backend.Result, error) {
	if len(opts.Env) > 0 {
		return t.ExecEnv(ctx, tool, args, opts.Env)
	}
	return t.Exec(ctx, tool, args)
}

// StreamOpts satisfies the backend.Backend options seam (see ExecOpts).
func (t *trackingBackend) StreamOpts(ctx context.Context, tool *backend.Tool, args []string, opts backend.ExecOptions) (<-chan backend.Event, error) {
	if len(opts.Env) > 0 {
		return t.StreamEnv(ctx, tool, args, opts.Env)
	}
	return t.Stream(ctx, tool, args)
}

// ExecOpts satisfies the backend.Backend options seam added in 18-01. It
// PRESERVES this fake's pre-18-01 dispatch exactly: Runner.Run used to call
// Backend.Exec and Runner.RunEnv used to call Backend.ExecEnv, and both now
// arrive here, so the env-set case forwards to ExecEnv and the zero case to Exec.
//
// It deliberately IGNORES opts.Stdin, opts.StdinPath and opts.Dir: this fake
// never receives them. A fake that needs to ASSERT on stdin must write its own
// ExecOpts instead of inheriting this forward — silently discarding the bytes is
// correct only because nothing here is testing them.
func (m *mockStreamBackend) ExecOpts(ctx context.Context, t *backend.Tool, args []string, opts backend.ExecOptions) (*backend.Result, error) {
	if len(opts.Env) > 0 {
		return m.ExecEnv(ctx, t, args, opts.Env)
	}
	return m.Exec(ctx, t, args)
}

// StreamOpts satisfies the backend.Backend options seam (see ExecOpts).
func (m *mockStreamBackend) StreamOpts(ctx context.Context, t *backend.Tool, args []string, opts backend.ExecOptions) (<-chan backend.Event, error) {
	if len(opts.Env) > 0 {
		return m.StreamEnv(ctx, t, args, opts.Env)
	}
	return m.Stream(ctx, t, args)
}

// ExecOpts satisfies the backend.Backend options seam added in 18-01. It
// PRESERVES this fake's pre-18-01 dispatch exactly: Runner.Run used to call
// Backend.Exec and Runner.RunEnv used to call Backend.ExecEnv, and both now
// arrive here, so the env-set case forwards to ExecEnv and the zero case to Exec.
//
// It deliberately IGNORES opts.Stdin, opts.StdinPath and opts.Dir: this fake
// never receives them. A fake that needs to ASSERT on stdin must write its own
// ExecOpts instead of inheriting this forward — silently discarding the bytes is
// correct only because nothing here is testing them.
func (m *streamTrackingBackend) ExecOpts(ctx context.Context, t *backend.Tool, args []string, opts backend.ExecOptions) (*backend.Result, error) {
	if len(opts.Env) > 0 {
		return m.ExecEnv(ctx, t, args, opts.Env)
	}
	return m.Exec(ctx, t, args)
}

// StreamOpts satisfies the backend.Backend options seam (see ExecOpts).
func (m *streamTrackingBackend) StreamOpts(ctx context.Context, t *backend.Tool, args []string, opts backend.ExecOptions) (<-chan backend.Event, error) {
	if len(opts.Env) > 0 {
		return m.StreamEnv(ctx, t, args, opts.Env)
	}
	return m.Stream(ctx, t, args)
}

// ExecOpts satisfies the backend.Backend options seam added in 18-01. It
// PRESERVES this fake's pre-18-01 dispatch exactly: Runner.Run used to call
// Backend.Exec and Runner.RunEnv used to call Backend.ExecEnv, and both now
// arrive here, so the env-set case forwards to ExecEnv and the zero case to Exec.
//
// It deliberately IGNORES opts.Stdin, opts.StdinPath and opts.Dir: this fake
// never receives them. A fake that needs to ASSERT on stdin must write its own
// ExecOpts instead of inheriting this forward — silently discarding the bytes is
// correct only because nothing here is testing them.
func (m *mockBackend) ExecOpts(ctx context.Context, t *backend.Tool, args []string, opts backend.ExecOptions) (*backend.Result, error) {
	if len(opts.Env) > 0 {
		return m.ExecEnv(ctx, t, args, opts.Env)
	}
	return m.Exec(ctx, t, args)
}

// StreamOpts satisfies the backend.Backend options seam (see ExecOpts).
func (m *mockBackend) StreamOpts(ctx context.Context, t *backend.Tool, args []string, opts backend.ExecOptions) (<-chan backend.Event, error) {
	if len(opts.Env) > 0 {
		return m.StreamEnv(ctx, t, args, opts.Env)
	}
	return m.Stream(ctx, t, args)
}

// ExecOpts satisfies the backend.Backend options seam added in 18-01. It
// PRESERVES this fake's pre-18-01 dispatch exactly: Runner.Run used to call
// Backend.Exec and Runner.RunEnv used to call Backend.ExecEnv, and both now
// arrive here, so the env-set case forwards to ExecEnv and the zero case to Exec.
//
// It deliberately IGNORES opts.Stdin, opts.StdinPath and opts.Dir: this fake
// never receives them. A fake that needs to ASSERT on stdin must write its own
// ExecOpts instead of inheriting this forward — silently discarding the bytes is
// correct only because nothing here is testing them.
func (m *mockMultiToolBackend) ExecOpts(ctx context.Context, t *backend.Tool, args []string, opts backend.ExecOptions) (*backend.Result, error) {
	if len(opts.Env) > 0 {
		return m.ExecEnv(ctx, t, args, opts.Env)
	}
	return m.Exec(ctx, t, args)
}

// StreamOpts satisfies the backend.Backend options seam (see ExecOpts).
func (m *mockMultiToolBackend) StreamOpts(ctx context.Context, t *backend.Tool, args []string, opts backend.ExecOptions) (<-chan backend.Event, error) {
	if len(opts.Env) > 0 {
		return m.StreamEnv(ctx, t, args, opts.Env)
	}
	return m.Stream(ctx, t, args)
}

// ExecOpts satisfies the backend.Backend options seam added in 18-01. It
// PRESERVES this fake's pre-18-01 dispatch exactly: Runner.Run used to call
// Backend.Exec and Runner.RunEnv used to call Backend.ExecEnv, and both now
// arrive here, so the env-set case forwards to ExecEnv and the zero case to Exec.
//
// It deliberately IGNORES opts.Stdin, opts.StdinPath and opts.Dir: this fake
// never receives them. A fake that needs to ASSERT on stdin must write its own
// ExecOpts instead of inheriting this forward — silently discarding the bytes is
// correct only because nothing here is testing them.
func (t *toolCallTracker) ExecOpts(ctx context.Context, tool *backend.Tool, args []string, opts backend.ExecOptions) (*backend.Result, error) {
	if len(opts.Env) > 0 {
		return t.ExecEnv(ctx, tool, args, opts.Env)
	}
	return t.Exec(ctx, tool, args)
}

// StreamOpts satisfies the backend.Backend options seam (see ExecOpts).
func (t *toolCallTracker) StreamOpts(ctx context.Context, tool *backend.Tool, args []string, opts backend.ExecOptions) (<-chan backend.Event, error) {
	if len(opts.Env) > 0 {
		return t.StreamEnv(ctx, tool, args, opts.Env)
	}
	return t.Stream(ctx, tool, args)
}

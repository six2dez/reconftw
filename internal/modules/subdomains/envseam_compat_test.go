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

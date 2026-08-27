// takeover_reason_test.go — a failed takeover tool is not a clean target.
//
// This branch swallowed dnstake's `flag provided but not defined: -f` as a Debug
// line and returned StatusDone with takeovers_found: 0. Takeover detection
// therefore produced zero for months while every run reported success, and the
// arg-vector bug was only found when a live parity run was compared against v1.

package subdomains_test

import (
	"context"
	stderrors "errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/task"
)

// failingBackend fails every dispatch, modelling a tool with a bad arg vector.
type failingBackend struct{ argCapturingBackend }

func (b *failingBackend) Exec(_ context.Context, _ *backend.Tool, _ []string) (*backend.Result, error) {
	return nil, stderrors.New("flag provided but not defined: -f")
}

func (b *failingBackend) ExecEnv(ctx context.Context, t *backend.Tool, a []string, _ []string) (*backend.Result, error) {
	return b.Exec(ctx, t, a)
}

func TestTakeoverToolFailureIsNotACleanTarget(t *testing.T) {
	for _, tc := range []struct{ task, tool string }{
		{"subdomains.takeover.dnstake", "dnstake"},
		{"subdomains.takeover.subzy", "subzy"},
	} {
		t.Run(tc.tool, func(t *testing.T) {
			workDir := t.TempDir()
			seedResolvedMerged(t, workDir, "api.example.com")

			reg := backend.NewToolRegistry()
			reg.Register(&backend.Tool{Name: tc.tool})
			app := newTestApp(workDir, backend.NewRunner(&failingBackend{}, reg, nil), &mockTree{})

			res, err := lookupSubTask(t, tc.task).Run(context.Background(), app)
			// CONTINUE_ON_TOOL_ERROR: the stage keeps going, so the error is nil.
			if err != nil {
				t.Fatalf("a degraded tool must not abort the stage: %v", err)
			}
			if res.Status == task.StatusDone {
				t.Fatal("a FAILED tool reported Done — indistinguishable from a clean target, " +
					"which is exactly how dnstake produced zero for months")
			}
			if res.Reason == "" {
				t.Fatal("no Reason: the operator sees [SKIP] and learns nothing")
			}
			if !strings.Contains(res.Reason, tc.tool) {
				t.Errorf("Reason %q does not name the tool", res.Reason)
			}
			if !strings.Contains(res.Reason, "flag provided but not defined") {
				t.Errorf("Reason %q dropped the tool's own account of the failure", res.Reason)
			}
			// The staging file is still written: the merge contract is unchanged.
			if len(res.Outputs) == 0 {
				t.Error("no staging file written — the merge contract was broken")
			}
		})
	}
}

// TestTakeoverCleanTargetIsStillDone is the counter-assertion that stops anyone
// "finishing the job" by turning every zero counter into a skip. A tool that ran
// successfully and found no vulnerable host is DONE — the target is clean.
func TestTakeoverCleanTargetIsStillDone(t *testing.T) {
	workDir := t.TempDir()
	seedResolvedMerged(t, workDir, "api.example.com")

	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "dnstake"})
	// argCapturingBackend succeeds and returns no output: a clean target.
	app := newTestApp(workDir, backend.NewRunner(&argCapturingBackend{}, reg, nil), &mockTree{})

	res, err := lookupSubTask(t, "subdomains.takeover.dnstake").Run(context.Background(), app)
	if err != nil {
		t.Fatalf("clean run errored: %v", err)
	}
	if res.Status != task.StatusDone {
		t.Errorf("Status = %q (%s), want done — a clean target is NOT a skip",
			res.Status, res.Reason)
	}
}

// seedResolvedMerged writes inputs/resolved.merged.txt, the file both takeover
// tasks read.
func seedResolvedMerged(t *testing.T, workDir string, hosts ...string) {
	t.Helper()
	dir := filepath.Join(workDir, "inputs")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("mkdir inputs: %v", err)
	}
	body := strings.Join(hosts, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "resolved.merged.txt"), []byte(body), 0o600); err != nil {
		t.Fatalf("seed resolved.merged.txt: %v", err)
	}
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
func (b *failingBackend) ExecOpts(ctx context.Context, t *backend.Tool, args []string, opts backend.ExecOptions) (*backend.Result, error) {
	if len(opts.Env) > 0 {
		return b.ExecEnv(ctx, t, args, opts.Env)
	}
	return b.Exec(ctx, t, args)
}

// StreamOpts satisfies the backend.Backend options seam (see ExecOpts).
func (b *failingBackend) StreamOpts(ctx context.Context, t *backend.Tool, args []string, opts backend.ExecOptions) (<-chan backend.Event, error) {
	if len(opts.Env) > 0 {
		return b.StreamEnv(ctx, t, args, opts.Env)
	}
	return b.Stream(ctx, t, args)
}

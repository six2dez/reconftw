// resolver_gate_test.go — the guard that closes the 2026-08-20 cutover blocker.
//
// A default v2 run carried Paths.Resolvers == "", handed puredns `-r "" -rt ""`,
// and died with `tool stream ended badly: exit status 1` inside the only
// PolicyFailFast stage group — after a 10-hour parity run. Two things were wrong
// and BOTH are asserted here, because fixing either alone leaves the failure
// reachable:
//
//  1. subdomains.resolvers.health DETECTED the empty path and returned
//     StatusSkipped, so the check could not stop the run it existed to protect.
//  2. subdomains.active had no resolver precondition of its own. Every task in
//     the subs-resolve group returns DependsOn() -> nil, so the group runs fully
//     concurrent — the health task is NOT a barrier, and relying on it to abort
//     first is a race that happened to be won on the day it was diagnosed.

package subdomains_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/task"
)

// newResolverGateApp builds an app whose resolver paths are set by the caller.
func newResolverGateApp(t *testing.T, workDir, resolvers, trusted string) *appctx.AppContext {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(workDir, "inputs"), 0o755); err != nil {
		t.Fatalf("mkdir inputs: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "inputs", "passive.merged.txt"),
		[]byte("api.example.com\n"), 0o644); err != nil {
		t.Fatalf("seed passive.merged.txt: %v", err)
	}
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "puredns"})
	app := newTestApp(workDir, backend.NewRunner(&mockStreamBackend{}, reg, nil), &mockTree{})
	app.Cfg.Paths.Resolvers = resolvers
	app.Cfg.Paths.ResolversTrusted = trusted
	return app
}

// TestSubActiveNoResolversErrors is the regression guard for the blocker itself.
// The failure it prevents is not "puredns errored" — it is a run that resolves
// nothing and still reports a result, which is what would have happened before
// phase 15 made Event.Err propagate.
func TestSubActiveNoResolversErrors(t *testing.T) {
	cases := []struct {
		name      string
		resolvers func(dir string) string
	}{
		{"unset path", func(string) string { return "" }},
		{"missing file", func(dir string) string { return filepath.Join(dir, "absent.txt") }},
		{"empty file", func(dir string) string {
			p := filepath.Join(dir, "empty.txt")
			if err := os.WriteFile(p, nil, 0o644); err != nil {
				t.Fatalf("write empty resolver file: %v", err)
			}
			return p
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			workDir := t.TempDir()
			app := newResolverGateApp(t, workDir, tc.resolvers(workDir), "")

			res, err := lookupSubTask(t, "subdomains.active").Run(context.Background(), app)
			if res.Status != task.StatusErrored {
				t.Fatalf("status = %q, want errored — a run with no resolvers must abort, "+
					"not resolve zero hosts and report success", res.Status)
			}
			if err == nil {
				t.Fatal("expected an error naming the resolver list")
			}
			// The message must point at the resolver list and the fix, not at puredns.
			if !strings.Contains(err.Error(), "resolvers") {
				t.Errorf("error does not name the resolver list: %v", err)
			}
			if !strings.Contains(err.Error(), "gen-resolvers") {
				t.Errorf("error gives the operator no remedy: %v", err)
			}
		})
	}
}

// TestResolversHealthErrorsOnZero pins action 2: the health check must be able to
// FAIL the run. Returning StatusSkipped is what let the 2026-08-20 run proceed to
// die four tasks later with an unrelated-looking puredns exit code.
func TestResolversHealthErrorsOnZero(t *testing.T) {
	workDir := t.TempDir()
	app := newResolverGateApp(t, workDir, "", "")

	res, err := lookupSubTask(t, "subdomains.resolvers.health").Run(context.Background(), app)
	if res.Status != task.StatusErrored {
		t.Fatalf("status = %q, want errored — a precondition check that cannot fail "+
			"the run is decoration", res.Status)
	}
	if err == nil || !strings.Contains(err.Error(), "gen-resolvers") {
		t.Errorf("health failure must carry the remedy; got: %v", err)
	}
}

// TestResolversHealthSkipsBelowMinimum keeps the pre-existing behaviour for the
// case that IS a plausible operator choice: a small but real resolver list. Only
// zero is fatal.
func TestResolversHealthSkipsBelowMinimum(t *testing.T) {
	workDir := t.TempDir()
	small := filepath.Join(workDir, "small.txt")
	if err := os.WriteFile(small, []byte("1.1.1.1\n"), 0o644); err != nil {
		t.Fatalf("write resolver file: %v", err)
	}
	app := newResolverGateApp(t, workDir, small, "")
	app.Cfg.Subdomains.Brute.MinResolvers = 50

	res, err := lookupSubTask(t, "subdomains.resolvers.health").Run(context.Background(), app)
	if err != nil {
		t.Fatalf("a small-but-real resolver list must not error: %v", err)
	}
	if res.Status != task.StatusSkipped {
		t.Errorf("status = %q, want skipped", res.Status)
	}
}

// TestSubActiveOmitsTrustedFlagWhenAbsent: `-rt ""` is what made puredns exit 1
// rather than fall back to its own trusted defaults. The flag must be omitted,
// not passed empty.
func TestSubActiveOmitsTrustedFlagWhenAbsent(t *testing.T) {
	workDir := t.TempDir()
	good := filepath.Join(workDir, "resolvers.txt")
	if err := os.WriteFile(good, []byte("1.1.1.1\n8.8.8.8\n"), 0o644); err != nil {
		t.Fatalf("write resolver file: %v", err)
	}

	tracker := &argCapturingBackend{}
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "puredns"})
	if err := os.MkdirAll(filepath.Join(workDir, "inputs"), 0o755); err != nil {
		t.Fatalf("mkdir inputs: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "inputs", "passive.merged.txt"),
		[]byte("api.example.com\n"), 0o644); err != nil {
		t.Fatalf("seed passive.merged.txt: %v", err)
	}
	app := newTestApp(workDir, backend.NewRunner(tracker, reg, nil), &mockTree{})
	app.Cfg.Paths.Resolvers = good
	app.Cfg.Paths.ResolversTrusted = filepath.Join(workDir, "absent-trusted.txt")

	if _, err := lookupSubTask(t, "subdomains.active").Run(context.Background(), app); err != nil {
		t.Fatalf("run: %v", err)
	}
	for i, a := range tracker.args {
		if a == "--resolvers-trusted" {
			t.Fatalf("puredns was passed --resolvers-trusted for a nonexistent list: %v", tracker.args)
		}
		if a == "" {
			t.Fatalf("puredns was passed an empty arg at position %d: %v", i, tracker.args)
		}
	}
}

// TestSubActivePurednsFlagNames pins the puredns arg vector to flag names the
// binary actually has. This is the regression guard for the SECOND layer of the
// 2026-08-20 cutover blocker, which the first fix uncovered.
//
// The code passed "-rt <path>". puredns has NO -rt shorthand: "-r" is the
// shorthand for --resolvers, so pflag binds "t" as its value, parses cleanly,
// and the tool dies with `unable to load public resolvers: open t: no such file
// or directory` — surfacing as the same generic "tool stream ended badly: exit
// status 1" that the empty-resolver-path bug produced. v1 uses the long
// --resolvers-trusted in all eight of its invocations (modules/subdomains.sh).
//
// It stayed hidden because the only test that claimed to validate arg vectors
// (internal/core/backend/smoke_test.go) is behind //go:build realtools, which
// NOTHING runs, and its failure sentinels only match parser REJECTIONS — never a
// shorthand collision the parser happily accepts.
func TestSubActivePurednsFlagNames(t *testing.T) {
	workDir := t.TempDir()
	list := filepath.Join(workDir, "resolvers.txt")
	trusted := filepath.Join(workDir, "trusted.txt")
	for _, p := range []string{list, trusted} {
		if err := os.WriteFile(p, []byte("1.1.1.1\n8.8.8.8\n"), 0o644); err != nil {
			t.Fatalf("seed %s: %v", p, err)
		}
	}
	if err := os.MkdirAll(filepath.Join(workDir, "inputs"), 0o755); err != nil {
		t.Fatalf("mkdir inputs: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "inputs", "passive.merged.txt"),
		[]byte("api.example.com\n"), 0o644); err != nil {
		t.Fatalf("seed passive.merged.txt: %v", err)
	}

	tracker := &argCapturingBackend{}
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "puredns"})
	app := newTestApp(workDir, backend.NewRunner(tracker, reg, nil), &mockTree{})
	app.Cfg.Paths.Resolvers = list
	app.Cfg.Paths.ResolversTrusted = trusted

	if _, err := lookupSubTask(t, "subdomains.active").Run(context.Background(), app); err != nil {
		t.Fatalf("run: %v", err)
	}

	// Every dash-prefixed token must be a flag puredns actually defines.
	// Source: `puredns resolve --help` (v2.1.1).
	known := map[string]bool{
		"-r": true, "--resolvers": true, "--resolvers-trusted": true,
		"-l": true, "--rate-limit": true, "--rate-limit-trusted": true,
		"-t": true, "--threads": true, "-n": true, "--wildcard-tests": true,
		"--wildcard-batch": true, "-b": true, "--bin": true,
		"-w": true, "--write": true, "--write-massdns": true, "--write-wildcards": true,
		"--skip-sanitize": true, "--skip-validation": true, "--skip-wildcard-filter": true,
		"--trusted-only": true, "-q": true, "--quiet": true, "--debug": true,
	}
	sawTrusted := false
	for _, a := range tracker.args {
		if !strings.HasPrefix(a, "-") {
			continue
		}
		if !known[a] {
			t.Errorf("puredns arg %q is not a flag puredns defines — check `puredns resolve --help`; "+
				"note that an UNDEFINED shorthand like -rt is silently accepted as -r with value \"t\"", a)
		}
		if a == "--resolvers-trusted" {
			sawTrusted = true
		}
	}
	if !sawTrusted {
		t.Error("the trusted resolver list was seeded but --resolvers-trusted was not passed")
	}
}

// argCapturingBackend records the arg vector of the first Stream call.
type argCapturingBackend struct {
	args []string
}

func (b *argCapturingBackend) Exec(_ context.Context, _ *backend.Tool, args []string) (*backend.Result, error) {
	b.args = args
	return &backend.Result{ExitCode: 0}, nil
}

func (b *argCapturingBackend) ExecEnv(ctx context.Context, t *backend.Tool, args []string, _ []string) (*backend.Result, error) {
	return b.Exec(ctx, t, args)
}

func (b *argCapturingBackend) StreamEnv(ctx context.Context, t *backend.Tool, args []string, _ []string) (<-chan backend.Event, error) {
	return b.Stream(ctx, t, args)
}

func (b *argCapturingBackend) HealthCheck(_ context.Context) error { return nil }
func (b *argCapturingBackend) Capacity() int                       { return 1 }

func (b *argCapturingBackend) Stream(_ context.Context, _ *backend.Tool, args []string) (<-chan backend.Event, error) {
	b.args = args
	ch := make(chan backend.Event)
	close(ch)
	return ch, nil
}

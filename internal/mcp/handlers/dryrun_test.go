// dryrun_test.go — acceptance gate 1 at the package boundary (F1).
//
// A dry run must leave the filesystem byte-for-byte unchanged: no workspace
// tree, no checkpoints.db, no data dir. Every RunXxxAsync used to call
// BootReconApp first and check opts.DryRun ~25 lines later, so the workspace had
// already been created and the SQLite checkpoint store opened by the time the
// early return fired.
//
// These tests assert on the ABSENCE of entries, never on their emptiness. A test
// that tolerates a created-but-empty directory is a test that would have passed
// against the bug.
package handlers_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/core/scheduler"
	"github.com/six2dez/reconftw/internal/mcp/handlers"
)

// TestDryRunHandlersCreateNothing runs all six entry points with DryRun=true and
// an OutputDir that does not exist, then asserts the enclosing temp directory has
// ZERO entries afterwards — the probe root was never created, so neither was the
// workspace tree or checkpoints.db inside it.
func TestDryRunHandlersCreateNothing(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		run  func(ctx context.Context, opts handlers.RunOptions) error
	}{
		{"subs", handlers.RunSubsAsync},
		{"web", handlers.RunWebAsync},
		{"vulns", handlers.RunVulnsAsync},
		{"osint", handlers.RunOSINTAsync},
		{"composite", func(ctx context.Context, opts handlers.RunOptions) error {
			return handlers.RunCompositeAsync(ctx, opts, handlers.ModeRecon)
		}},
		{"monitor", func(ctx context.Context, opts handlers.RunOptions) error {
			return handlers.RunMonitorAsync(ctx, opts, handlers.MonitorOptions{
				Mode:      handlers.ModeRecon,
				MaxCycles: 1,
			})
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			work := t.TempDir()
			probe := filepath.Join(work, "probe")

			afterBootCalls := 0
			var gotCfgNonNil bool
			var gotWorkDir string

			opts := handlers.RunOptions{
				Target:    "example.com",
				DryRun:    true,
				OutputDir: probe,
				Scheduler: scheduler.NewScheduler(0, 0, nil, nil),
				AfterBoot: func(boot handlers.AppBoot) {
					afterBootCalls++
					gotCfgNonNil = boot.Cfg != nil
					gotWorkDir = boot.WorkDir
				},
			}

			if err := tc.run(context.Background(), opts); err != nil {
				t.Fatalf("%s dry run returned an error: %v", tc.name, err)
			}

			// The dry-run report must still answer "where would this write?".
			if afterBootCalls != 1 {
				t.Errorf("AfterBoot called %d times, want exactly 1 — the dry-run "+
					"report the operator asked for is produced by this callback",
					afterBootCalls)
			}
			if !gotCfgNonNil {
				t.Error("AfterBoot received a nil Cfg — the dry-run consumer needs the resolved config")
			}
			if !strings.HasPrefix(gotWorkDir, probe+string(os.PathSeparator)) {
				t.Errorf("dry-run WorkDir = %q, want a path under the -o root %q", gotWorkDir, probe)
			}

			// The assertion that matters: nothing was created.
			entries, err := os.ReadDir(work)
			if err != nil {
				t.Fatalf("ReadDir(%s): %v", work, err)
			}
			if len(entries) != 0 {
				var names []string
				for _, e := range entries {
					names = append(names, e.Name())
				}
				t.Fatalf("%s dry run created %d entr(ies) in a pristine root: %v — "+
					"a dry run must leave the filesystem unchanged",
					tc.name, len(entries), names)
			}
			if _, statErr := os.Stat(probe); statErr == nil {
				t.Errorf("%s dry run created the workspace root %s", tc.name, probe)
			}
			if _, statErr := os.Stat(filepath.Join(gotWorkDir, "checkpoints.db")); statErr == nil {
				t.Errorf("%s dry run created checkpoints.db under %s", tc.name, gotWorkDir)
			}
		})
	}
}

// TestDryRunWorkDirMatchesRealWorkspace is the path-agreement proof: the
// directory a dry run REPORTS must be the directory a real run CREATES.
//
// The CIDR case is the one that matters. A locally re-derived slug looks correct
// for plain domains and silently diverges for exactly the prefix-carrying targets
// canonical identity exists to disambiguate, so this compares against a real
// output.WorkspaceInit rather than against a hand-written expectation.
func TestDryRunWorkDirMatchesRealWorkspace(t *testing.T) {
	t.Parallel()

	for _, target := range []string{"example.com", "10.0.0.0/24", "10.0.0.0/16", "10.0.0.0", "2001:db8::1"} {
		t.Run(target, func(t *testing.T) {
			t.Parallel()

			dryRoot := filepath.Join(t.TempDir(), "dry")
			realRoot := t.TempDir()

			boot, err := handlers.ResolveDryRunBoot(handlers.RunOptions{
				Target:    target,
				DryRun:    true,
				OutputDir: dryRoot,
			})
			if err != nil {
				t.Fatalf("ResolveDryRunBoot(%q): %v", target, err)
			}

			realWorkdir, err := output.WorkspaceInit(realRoot, target)
			if err != nil {
				t.Fatalf("WorkspaceInit(%q): %v", target, err)
			}

			// Compare the full path with the root substituted, which catches a
			// divergence anywhere in the slug rather than only in its last element.
			wantUnderDryRoot := filepath.Join(dryRoot, filepath.Base(realWorkdir))
			if boot.WorkDir != wantUnderDryRoot {
				t.Errorf("dry-run WorkDir = %q, real WorkspaceInit produced %q (rooted: %q)\n"+
					"a dry run that names a directory the real run never touches is a "+
					"wrong answer delivered confidently",
					boot.WorkDir, realWorkdir, wantUnderDryRoot)
			}
			if filepath.Base(boot.WorkDir) != filepath.Base(realWorkdir) {
				t.Errorf("slug mismatch: dry %q vs real %q",
					filepath.Base(boot.WorkDir), filepath.Base(realWorkdir))
			}

			// The dry root itself must not exist.
			if _, statErr := os.Stat(dryRoot); statErr == nil {
				t.Errorf("ResolveDryRunBoot created %s", dryRoot)
			}
		})
	}
}

// TestDryRunDistinctPrefixesStayDistinct guards the property gate 2 established
// at the identity layer, at THIS layer: three targets that differ only by prefix
// must be reported as three different workspaces by the dry run too.
func TestDryRunDistinctPrefixesStayDistinct(t *testing.T) {
	t.Parallel()

	root := filepath.Join(t.TempDir(), "root")
	seen := map[string]string{}
	for _, target := range []string{"10.0.0.0/24", "10.0.0.0/16", "10.0.0.0"} {
		boot, err := handlers.ResolveDryRunBoot(handlers.RunOptions{
			Target:    target,
			DryRun:    true,
			OutputDir: root,
		})
		if err != nil {
			t.Fatalf("ResolveDryRunBoot(%q): %v", target, err)
		}
		if prev, dup := seen[boot.WorkDir]; dup {
			t.Fatalf("targets %q and %q both report workspace %q", prev, target, boot.WorkDir)
		}
		seen[boot.WorkDir] = target
	}
}

// TestResolveDryRunBootRejectsUnclassifiableTarget: a dry run must fail on a
// target a real run would refuse, rather than reporting a plausible-looking plan.
func TestResolveDryRunBootRejectsUnclassifiableTarget(t *testing.T) {
	t.Parallel()

	for _, target := range []string{"", "   "} {
		_, err := handlers.ResolveDryRunBoot(handlers.RunOptions{
			Target:    target,
			DryRun:    true,
			OutputDir: t.TempDir(),
		})
		if err == nil {
			t.Errorf("ResolveDryRunBoot(%q): want non-nil error, got nil", target)
		}
	}
}

// TestResolveRunPlanIsSideEffectFree points ResolveRunPlan at a nonexistent
// output root and asserts it stays nonexistent. ResolveRunPlan is the whole
// dry-run path, so any mutation added to it re-opens F1.
func TestResolveRunPlanIsSideEffectFree(t *testing.T) {
	t.Parallel()

	work := t.TempDir()
	probe := filepath.Join(work, "never", "created")

	plan, err := handlers.ResolveRunPlan(handlers.RunOptions{
		Target:    "example.com",
		OutputDir: probe,
	})
	if err != nil {
		t.Fatalf("ResolveRunPlan: %v", err)
	}
	if plan.Cfg == nil {
		t.Fatal("ResolveRunPlan returned a nil Cfg")
	}
	if plan.Target == nil {
		t.Fatal("ResolveRunPlan returned a nil Target")
	}
	if plan.WorkspaceRoot != probe {
		t.Errorf("WorkspaceRoot = %q, want the -o root %q", plan.WorkspaceRoot, probe)
	}
	if plan.Target.WorkDir != "" {
		t.Errorf("plan.Target.WorkDir = %q, want empty — a resolved plan owns no workspace",
			plan.Target.WorkDir)
	}
	if _, statErr := os.Stat(probe); statErr == nil {
		t.Errorf("ResolveRunPlan created %s", probe)
	}
	entries, err := os.ReadDir(work)
	if err != nil {
		t.Fatalf("ReadDir(%s): %v", work, err)
	}
	if len(entries) != 0 {
		t.Errorf("ResolveRunPlan created %d entr(ies) in a pristine root", len(entries))
	}
}

// TestResolveRunPlanNeedsNoScheduler documents the deliberate asymmetry:
// enumerating a plan needs no scheduler, while BootReconApp still refuses a nil
// one (T-08-03-02).
func TestResolveRunPlanNeedsNoScheduler(t *testing.T) {
	t.Parallel()

	if _, err := handlers.ResolveRunPlan(handlers.RunOptions{
		Target:    "example.com",
		Scheduler: nil,
	}); err != nil {
		t.Errorf("ResolveRunPlan with nil Scheduler: %v", err)
	}
}

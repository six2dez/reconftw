// Tests for INTEG-03 resume-across-runs wiring in BootReconApp:
//   - Scheduler.Hash is wired to a REAL InputHash (taskName + target +
//     cfgSnapshot + TargetListPath + wordlists), not the taskName-only degenerate.
//   - The hash invalidates on target / config / TargetListPath change.
//   - opts.Force sets cfg.Advanced.Diff → Scheduler.ForceRerun.
//   - Two boot+run cycles against the same target share ONE stable workspace,
//     so the second cycle hits the persisted checkpoint and skips completed work;
//     --force re-executes it.
//
// Workspace isolation: each test writes a throwaway reconftw.toml whose
// [paths].data_dir points at a fresh t.TempDir(), so BootReconApp's stable
// per-target workspace (and its checkpoints.db) lands under the temp dir instead
// of polluting ./workspaces or colliding with peer tests.
package handlers_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/checkpoint"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/scheduler"
	"github.com/six2dez/reconftw/internal/core/task"
	"github.com/six2dez/reconftw/internal/mcp/handlers"
)

// resumeTask is a minimal controllable task.Task that records how many times it
// ran. Module "subdomains" → fail_fast policy; a nil-error Run → status=done.
type resumeTask struct {
	name    string
	started atomic.Int32
}

func (r *resumeTask) Name() string                { return r.name }
func (r *resumeTask) Module() string              { return "subdomains" }
func (r *resumeTask) Description() string         { return "resume test " + r.name }
func (r *resumeTask) Enabled(*config.Config) bool { return true }
func (r *resumeTask) DependsOn() []string         { return nil }
func (r *resumeTask) Run(context.Context, *appctx.AppContext) (task.Result, error) {
	r.started.Add(1)
	return task.Result{Status: task.StatusDone, Outputs: []string{"out/" + r.name}}, nil
}

// resumeConfigPath writes a minimal reconftw.toml that pins data_dir to dataDir
// and returns its path.
func resumeConfigPath(t *testing.T, dataDir string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "reconftw.toml")
	body := fmt.Sprintf("[paths]\ndata_dir = %q\n", dataDir)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return p
}

// resumeBoot boots an app with a per-scan scheduler under an isolated data_dir.
// When opts.ConfigPath is empty a fresh data_dir-pinned config is generated.
func resumeBoot(t *testing.T, dataDir string, opts handlers.RunOptions) (handlers.AppBoot, *scheduler.Scheduler) {
	t.Helper()
	sched := scheduler.NewScheduler(0, 0, nil, nil)
	opts.Scheduler = sched
	if opts.ConfigPath == "" {
		opts.ConfigPath = resumeConfigPath(t, dataDir)
	}
	boot, err := handlers.BootReconApp(context.Background(), opts)
	if err != nil {
		t.Fatalf("BootReconApp(target=%q): %v", opts.Target, err)
	}
	return boot, sched
}

// resumeCloseCheckpoint releases the SQLite checkpoint handle AND the F4
// workspace lock, so the next boot against the same stable workspace reopens it
// cleanly instead of being rejected with "target already running".
//
// It delegates to AppBoot.Close — the same single cleanup path the six
// production handlers defer. Hand-rolling the checkpoint close here left the
// lock held; whether the next boot then succeeded depended on when the GC ran
// os.File's finaliser, which is exactly the kind of flake a test must not have.
func resumeCloseCheckpoint(b handlers.AppBoot) {
	_ = b.Close()
}

// resumeWordlistsLock mirrors handlers.wordlistsLockContent so the exact-hash
// assertion below reconstructs the same wordlists slice BootReconApp folds in.
func resumeWordlistsLock(cfg *config.Config) []byte {
	var buf bytes.Buffer
	for _, p := range []string{cfg.Paths.SubsWordlist, cfg.Paths.SubsWordlistBig, cfg.Paths.FuzzWordlist} {
		if p == "" {
			continue
		}
		info, err := os.Stat(p)
		if err != nil {
			continue
		}
		fmt.Fprintf(&buf, "%s\x00%d\x00%d\n", p, info.Size(), info.ModTime().UnixNano())
	}
	return buf.Bytes()
}

// resumeHashFor boots, reads the wired hash for a fixed task, then closes.
func resumeHashFor(t *testing.T, dataDir string, opts handlers.RunOptions) string {
	t.Helper()
	boot, sched := resumeBoot(t, dataDir, opts)
	defer resumeCloseCheckpoint(boot)
	if sched.Hash == nil {
		t.Fatal("BootReconApp did not wire Scheduler.Hash (nil)")
	}
	return sched.Hash("subdomains.passive.subfinder", "ignored")
}

// TestBootReconAppWiresRealInputHash: the wired hash equals
// checkpoint.InputHash(taskName, target, cfgSlice||\0||"tlp="||TargetListPath, wl)
// and is NOT the old taskName-only degenerate.
func TestBootReconAppWiresRealInputHash(t *testing.T) {
	dataDir := t.TempDir()
	boot, sched := resumeBoot(t, dataDir, handlers.RunOptions{Target: "example.com"})
	defer resumeCloseCheckpoint(boot)

	if sched.Hash == nil {
		t.Fatal("Scheduler.Hash not wired")
	}
	const taskName = "subdomains.passive.subfinder"
	got := sched.Hash(taskName, "scheduler-passes-empty")

	cfgSlice, err := config.SnapshotBytes(boot.Cfg)
	if err != nil {
		t.Fatalf("SnapshotBytes: %v", err)
	}
	// Formula: cfgSlice \0 "tlp=" <TargetListPath> \0 "gen=" <RunGeneration>.
	// The gen= component was added so monitor cycles hash differently; without
	// it every cycle after the first skipped every task.
	hashSlice := append(append(append([]byte{}, cfgSlice...), 0), []byte("tlp=")...)
	hashSlice = append(append(hashSlice, 0), []byte("gen=")...)
	want := checkpoint.InputHash(taskName, boot.App.Target.Domain, hashSlice, resumeWordlistsLock(boot.Cfg))
	if got != want {
		t.Errorf("wired hash = %s\n           want %s (InputHash formula mismatch)", got, want)
	}
	if degenerate := checkpoint.InputHash(taskName, "", nil, nil); got == degenerate {
		t.Error("wired hash degenerated to taskName-only — target/cfg not folded in")
	}
}

// TestInputHashDiffersOnTargetChange: different targets → different hashes.
func TestInputHashDiffersOnTargetChange(t *testing.T) {
	dataDir := t.TempDir()
	hA := resumeHashFor(t, dataDir, handlers.RunOptions{Target: "alpha.example.com"})
	hB := resumeHashFor(t, dataDir, handlers.RunOptions{Target: "beta.example.com"})
	if hA == hB {
		t.Errorf("InputHash identical for different targets (%s) — target not folded into hash", hA)
	}
}

// TestInputHashDiffersOnConfigChange: a single config byte change (via
// ConfigTransform) changes the hash — the cfg-slice invalidates the checkpoint.
func TestInputHashDiffersOnConfigChange(t *testing.T) {
	dataDir := t.TempDir()
	cfgPath := resumeConfigPath(t, dataDir)
	base := resumeHashFor(t, dataDir, handlers.RunOptions{Target: "example.com", ConfigPath: cfgPath})
	changed := resumeHashFor(t, dataDir, handlers.RunOptions{
		Target:     "example.com",
		ConfigPath: cfgPath,
		ConfigTransform: func(c *config.Config) {
			c.Concurrency.MaxJobs = c.Concurrency.MaxJobs + 7
		},
	})
	if base == changed {
		t.Error("InputHash unchanged after a config change — cfg-slice not folded into hash")
	}
}

// TestInputHashDiffersOnTargetListPath: setting TargetListPath changes the hash
// (the INTEG-04 bridge — an incremental re-feed genuinely re-runs).
func TestInputHashDiffersOnTargetListPath(t *testing.T) {
	dataDir := t.TempDir()
	cfgPath := resumeConfigPath(t, dataDir)
	empty := resumeHashFor(t, dataDir, handlers.RunOptions{Target: "example.com", ConfigPath: cfgPath})
	listed := resumeHashFor(t, dataDir, handlers.RunOptions{
		Target:         "example.com",
		ConfigPath:     cfgPath,
		TargetListPath: "/tmp/incremental-new-assets.txt",
	})
	if empty == listed {
		t.Error("InputHash unchanged when TargetListPath is set — list/incremental re-feed would NOT re-run")
	}
}

// TestBootReconAppForceWiresForceRerun: opts.Force drives cfg.Advanced.Diff and
// Scheduler.ForceRerun; without it both stay false.
func TestBootReconAppForceWiresForceRerun(t *testing.T) {
	dataDir := t.TempDir()

	boot0, s0 := resumeBoot(t, dataDir, handlers.RunOptions{Target: "example.com"})
	defer resumeCloseCheckpoint(boot0)
	if s0.ForceRerun {
		t.Error("Force=false but Scheduler.ForceRerun=true")
	}
	if boot0.Cfg.Advanced.Diff {
		t.Error("Force=false but cfg.Advanced.Diff=true")
	}

	boot1, s1 := resumeBoot(t, dataDir, handlers.RunOptions{Target: "example.org", Force: true})
	defer resumeCloseCheckpoint(boot1)
	if !s1.ForceRerun {
		t.Error("Force=true but Scheduler.ForceRerun=false")
	}
	if !boot1.Cfg.Advanced.Diff {
		t.Error("Force=true but cfg.Advanced.Diff=false")
	}
}

// TestResumeAcrossRunsSkipsCompleted: cycle 1 completes a task; cycle 2 against
// the same target reuses the SAME workspace and hits the persisted checkpoint,
// skipping the completed task. This is the core INTEG-03 proof.
func TestResumeAcrossRunsSkipsCompleted(t *testing.T) {
	dataDir := t.TempDir()
	cfgPath := resumeConfigPath(t, dataDir)
	ctx := context.Background()
	const target = "example.com"
	const taskName = "subdomains.passive.subfinder"

	// Cycle 1: run to completion (records a done checkpoint).
	boot1, sched1 := resumeBoot(t, dataDir, handlers.RunOptions{Target: target, ConfigPath: cfgPath})
	ws1 := boot1.WorkDir
	sched1.Checkpoint = boot1.App.Checkpoint
	t1 := &resumeTask{name: taskName}
	if err := sched1.RunStage(ctx, "subdomains", []task.Task{t1}); err != nil {
		resumeCloseCheckpoint(boot1)
		t.Fatalf("cycle 1 RunStage: %v", err)
	}
	if t1.started.Load() != 1 {
		resumeCloseCheckpoint(boot1)
		t.Fatalf("cycle 1: task did not run (started=%d)", t1.started.Load())
	}
	resumeCloseCheckpoint(boot1) // flush WAL + release before cycle 2 reopens

	// Cycle 2: same target + config → SAME workspace, task SKIPPED (checkpoint hit).
	boot2, sched2 := resumeBoot(t, dataDir, handlers.RunOptions{Target: target, ConfigPath: cfgPath})
	defer resumeCloseCheckpoint(boot2)
	if boot2.WorkDir != ws1 {
		t.Fatalf("workspace not stable across runs: cycle1=%q cycle2=%q", ws1, boot2.WorkDir)
	}
	sched2.Checkpoint = boot2.App.Checkpoint
	t2 := &resumeTask{name: taskName}
	if err := sched2.RunStage(ctx, "subdomains", []task.Task{t2}); err != nil {
		t.Fatalf("cycle 2 RunStage: %v", err)
	}
	if t2.started.Load() != 0 {
		t.Errorf("cycle 2: completed task re-ran (started=%d), want 0 — checkpoints.db did NOT persist across runs",
			t2.started.Load())
	}
}

// TestForceRerunReExecutesAcrossRuns: after a completed run, a --force run
// re-executes the task (ForceRerun bypasses the checkpoint hit) while still
// recording checkpoints.
func TestForceRerunReExecutesAcrossRuns(t *testing.T) {
	dataDir := t.TempDir()
	cfgPath := resumeConfigPath(t, dataDir)
	ctx := context.Background()
	const target = "example.com"
	const taskName = "subdomains.passive.subfinder"

	boot1, sched1 := resumeBoot(t, dataDir, handlers.RunOptions{Target: target, ConfigPath: cfgPath})
	sched1.Checkpoint = boot1.App.Checkpoint
	t1 := &resumeTask{name: taskName}
	if err := sched1.RunStage(ctx, "subdomains", []task.Task{t1}); err != nil {
		resumeCloseCheckpoint(boot1)
		t.Fatalf("cycle 1 RunStage: %v", err)
	}
	resumeCloseCheckpoint(boot1)

	boot2, sched2 := resumeBoot(t, dataDir, handlers.RunOptions{Target: target, ConfigPath: cfgPath, Force: true})
	defer resumeCloseCheckpoint(boot2)
	if !sched2.ForceRerun {
		t.Fatal("Force=true did not wire ForceRerun")
	}
	sched2.Checkpoint = boot2.App.Checkpoint
	t2 := &resumeTask{name: taskName}
	if err := sched2.RunStage(ctx, "subdomains", []task.Task{t2}); err != nil {
		t.Fatalf("cycle 2 (force) RunStage: %v", err)
	}
	if t2.started.Load() != 1 {
		t.Errorf("cycle 2 (force): task did NOT re-run (started=%d), want 1", t2.started.Load())
	}
}

// TestInputHashDiffersOnRunGeneration is the monitor fix expressed as a hash
// property: two runs identical in every other respect must hash differently
// when the generation differs, or checkpoint.Done() skips the second one.
func TestInputHashDiffersOnRunGeneration(t *testing.T) {
	dataDir := t.TempDir()
	h1 := resumeHashFor(t, dataDir, handlers.RunOptions{Target: "example.com", RunGeneration: "cycle-1"})
	h2 := resumeHashFor(t, dataDir, handlers.RunOptions{Target: "example.com", RunGeneration: "cycle-2"})
	if h1 == h2 {
		t.Error("two monitor cycles produced the same input hash — every task in " +
			"cycle 2 would be skipped as already done, so the monitor could never " +
			"observe a change")
	}
	// And an unset generation must still be stable, so ordinary scans keep
	// resuming from their checkpoints exactly as before.
	a := resumeHashFor(t, dataDir, handlers.RunOptions{Target: "example.com"})
	b := resumeHashFor(t, dataDir, handlers.RunOptions{Target: "example.com"})
	if a != b {
		t.Error("an ordinary scan's hash is not stable — resume-from-checkpoint is broken")
	}
}

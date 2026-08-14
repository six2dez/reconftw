// Internal-package tests for the legacy-workspace adoption race.
//
// These live in `package output` (mirroring atomic_internal_test.go) because
// the barrier they need is the unexported `beforeAdoptRename` seam. The
// external init_test.go covers everything that the public API can reach; only
// the concurrency proof and the production-nil guard need to be in here.
package output

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestBeforeAdoptRenameIsNilInProduction is the guard that stops the test seam
// from being left wired in. A non-nil hook in a shipped binary would run
// arbitrary code on the hottest path in the package, immediately before a
// rename that moves a whole engagement.
//
// It is deliberately NOT parallel and does NOT set the hook, so it observes the
// package's initial state.
func TestBeforeAdoptRenameIsNilInProduction(t *testing.T) {
	if beforeAdoptRename != nil {
		t.Fatal("beforeAdoptRename is non-nil: a test seam was left wired into production")
	}
}

// TestAdoptLegacyWorkspaceConcurrentConverges is the F4-adjacent race proof.
//
// WorkspaceInit runs BEFORE the workspace flock is acquired, so two first runs
// after an upgrade can both reach os.Rename. One wins; the loser gets ENOENT on
// the rename SOURCE and must converge on the winner's directory rather than
// failing a legitimate scan.
//
// WHY THE BARRIER IS MANDATORY. Two goroutines with no synchronisation are NOT
// sufficient and must not be accepted as a proof: if they serialise, the second
// finds legacyPath already gone at step 2 and returns cleanly through the
// ordinary "no legacy directory" path, never reaching the rename and never
// exercising the os.IsNotExist convergence branch — so the test passes
// identically with the fix reverted. The hook forces BOTH goroutines past the
// step-2/step-3 existence checks before either renames.
func TestAdoptLegacyWorkspaceConcurrentConverges(t *testing.T) {
	root := t.TempDir()
	legacy := filepath.Join(root, "example.com")
	seeded := map[string]string{
		"checkpoints.db":           "run-1-checkpoints",
		"inputs/x.jsonl":           `{"staged":true}`,
		"artefacts/findings.jsonl": `{"finding":"critical"}`,
		"_compat/subdomains.txt":   "x.example.com",
	}
	for rel, content := range seeded {
		full := filepath.Join(legacy, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("seed mkdir: %v", err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("seed write %s: %v", rel, err)
		}
	}

	const goroutines = 2
	var (
		arrived      sync.WaitGroup
		arrivals     atomic.Int32
		barrierStuck atomic.Bool
	)
	arrived.Add(goroutines)

	beforeAdoptRename = func() {
		arrivals.Add(1)
		arrived.Done()
		released := make(chan struct{})
		go func() {
			arrived.Wait()
			close(released)
		}()
		select {
		case <-released:
		case <-time.After(30 * time.Second):
			// Never expected: the hook sits immediately before the rename, so
			// neither goroutine can observe the other's rename before both have
			// arrived. Time out loudly instead of hanging the suite.
			barrierStuck.Store(true)
		}
	}
	t.Cleanup(func() { beforeAdoptRename = nil })

	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		paths []string
		errs  []error
	)
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			ws, err := WorkspaceInit(root, "example.com")
			mu.Lock()
			paths = append(paths, ws)
			errs = append(errs, err)
			mu.Unlock()
		}()
	}
	wg.Wait()

	if barrierStuck.Load() {
		t.Fatal("adoption barrier timed out — the convergence branch was NOT exercised")
	}
	if got := arrivals.Load(); got != goroutines {
		t.Fatalf("only %d of %d goroutines reached the pre-rename seam; the race was not exercised", got, goroutines)
	}

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: WorkspaceInit returned %v; a lost adoption race must converge, not fail", i, err)
		}
	}
	if t.Failed() {
		return
	}
	if paths[0] != paths[1] {
		t.Fatalf("goroutines disagreed on the workspace: %q vs %q", paths[0], paths[1])
	}

	ws := paths[0]
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Errorf("legacy directory survived adoption (stat err = %v)", err)
	}
	for rel, content := range seeded {
		data, err := os.ReadFile(filepath.Join(ws, filepath.FromSlash(rel)))
		if err != nil {
			t.Errorf("adopted workspace lost %s: %v", rel, err)
			continue
		}
		if string(data) != content {
			t.Errorf("%s content = %q, want %q", rel, data, content)
		}
	}

	// Exactly one workspace directory: nothing was duplicated by the race.
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	dirs := 0
	for _, e := range entries {
		if e.IsDir() {
			dirs++
		}
	}
	if dirs != 1 {
		t.Errorf("root holds %d directories after the race, want exactly 1", dirs)
	}
}

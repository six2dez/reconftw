// External test package: the workspace lock is exercised exactly as callers
// use it (output.AcquireWorkspaceLock / Lock.Release), with no access to
// package internals.
//
// The load-bearing test here is TestLockCrossProcessContention. An in-process
// contention test alone proves nothing: it would pass identically if the
// "lock" were a plain sync.Mutex, which is precisely the failure mode F4 is
// about (two OS PROCESSES sharing one workspace). The cross-process test
// spawns this same test binary as a helper, has it hold the lock, and asserts
// the parent is rejected — then SIGKILLs the helper and asserts the next
// acquisition SUCCEEDS, which is the evidence that no stale-lock timeout or
// PID probe is needed.
//
// Source: .planning/phases/15-release-gates-run-isolation-store-integrity/15-09-PLAN.md
package output_test

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/six2dez/reconftw/internal/core/output"
)

// lockHelperEnv names the workspace directory the helper subprocess should
// lock. Its presence is what turns TestLockHelperProcess from a skipped no-op
// (in an ordinary test run) into the helper (in the spawned run).
const lockHelperEnv = "RECONFTW_LOCK_HELPER_DIR"

// TestLockHelperProcess is the helper half of TestLockCrossProcessContention.
// It is skipped in every ordinary run.
func TestLockHelperProcess(t *testing.T) {
	dir := os.Getenv(lockHelperEnv)
	if dir == "" {
		t.Skip("not the lock helper subprocess")
	}
	l, err := output.AcquireWorkspaceLock(dir)
	if err != nil {
		fmt.Printf("HELPER-ERROR %v\n", err)
		_ = os.Stdout.Sync() // best-effort flush before _exit
		os.Exit(3)
	}
	fmt.Printf("LOCKED %d\n", os.Getpid())
	_ = os.Stdout.Sync() // best-effort flush before the parent reads
	// Hold the lock until the parent kills us. A bounded sleep (rather than a
	// bare block) keeps a leaked helper from surviving the test run, and gives
	// the runtime a pending timer so the deadlock detector stays quiet.
	time.Sleep(90 * time.Second)
	_ = l.Release()
}

func TestLockAcquireRejectsSecondInProcess(t *testing.T) {
	dir := t.TempDir()

	first, err := output.AcquireWorkspaceLock(dir)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}

	second, err := output.AcquireWorkspaceLock(dir)
	if err == nil {
		_ = second.Release()
		t.Fatal("second acquire succeeded; the workspace lock is not exclusive")
	}
	if !errors.Is(err, output.ErrWorkspaceBusy) {
		t.Fatalf("second acquire: want ErrWorkspaceBusy, got %v", err)
	}
	if second != nil {
		t.Fatalf("a rejected acquire must return a nil *Lock, got %#v", second)
	}

	if err := first.Release(); err != nil {
		t.Fatalf("release: %v", err)
	}

	third, err := output.AcquireWorkspaceLock(dir)
	if err != nil {
		t.Fatalf("third acquire after release: %v", err)
	}
	if err := third.Release(); err != nil {
		t.Fatalf("release third: %v", err)
	}
}

func TestLockReleaseIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	l, err := output.AcquireWorkspaceLock(dir)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if err := l.Release(); err != nil {
		t.Fatalf("first release: %v", err)
	}
	if err := l.Release(); err != nil {
		t.Fatalf("second release must be a nil no-op, got %v", err)
	}
	if err := l.Release(); err != nil {
		t.Fatalf("third release must be a nil no-op, got %v", err)
	}

	// A nil *Lock releases successfully — this is what makes an unconditional
	// deferred release safe on a dry-run boot that holds no lock.
	var nilLock *output.Lock
	if err := nilLock.Release(); err != nil {
		t.Fatalf("nil Lock.Release must be a no-op, got %v", err)
	}
	if got := nilLock.Path(); got != "" {
		t.Fatalf("nil Lock.Path() = %q, want empty", got)
	}
}

func TestLockDistinctWorkspacesDoNotContend(t *testing.T) {
	a := t.TempDir()
	b := t.TempDir()

	la, err := output.AcquireWorkspaceLock(a)
	if err != nil {
		t.Fatalf("acquire a: %v", err)
	}
	defer func() { _ = la.Release() }()

	lb, err := output.AcquireWorkspaceLock(b)
	if err != nil {
		t.Fatalf("acquire b while a is held: %v — the lock must be per-workspace, not global", err)
	}
	defer func() { _ = lb.Release() }()

	if la.Path() == lb.Path() {
		t.Fatalf("two workspaces resolved to one lock path: %q", la.Path())
	}
}

func TestLockFileRemovedOnRelease(t *testing.T) {
	dir := t.TempDir()
	l, err := output.AcquireWorkspaceLock(dir)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	lockPath := filepath.Join(dir, output.LockFileName)
	if _, err := os.Stat(lockPath); err != nil {
		t.Fatalf("lock file must exist while held: %v", err)
	}
	if err := l.Release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Fatalf("lock file must be removed on release, stat err = %v", err)
	}
}

func TestLockPayloadNamesOwner(t *testing.T) {
	root := t.TempDir()
	ws, err := output.WorkspaceInit(root, "example.com")
	if err != nil {
		t.Fatalf("workspace init: %v", err)
	}

	l, err := output.AcquireWorkspaceLock(ws)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer func() { _ = l.Release() }()

	data, err := os.ReadFile(filepath.Join(ws, output.LockFileName))
	if err != nil {
		t.Fatalf("read lock file: %v", err)
	}
	var p output.LockPayload
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatalf("lock payload is not JSON (%q): %v", string(data), err)
	}
	if p.PID != os.Getpid() {
		t.Fatalf("payload PID = %d, want %d", p.PID, os.Getpid())
	}
	if _, err := time.Parse(time.RFC3339, p.StartedAt); err != nil {
		t.Fatalf("payload started_at %q is not RFC3339: %v", p.StartedAt, err)
	}
	id, err := output.CanonicalTargetID("example.com")
	if err != nil {
		t.Fatalf("canonical id: %v", err)
	}
	if p.Canonical != id.Canonical || p.Kind != id.Kind || p.Slug != id.Slug {
		t.Fatalf("payload identity = %+v, want canonical=%q kind=%q slug=%q",
			p, id.Canonical, id.Kind, id.Slug)
	}
}

// TestLockCrossProcessContention is the real proof: a separate OS process holds
// the lock and this process is rejected by name, then a SIGKILLed holder leaves
// an immediately acquirable workspace.
func TestLockCrossProcessContention(t *testing.T) {
	dir := t.TempDir()

	cmd := exec.Command(os.Args[0], "-test.run=^TestLockHelperProcess$") //nolint:gosec // re-executes this test binary
	cmd.Env = append(os.Environ(), lockHelperEnv+"="+dir)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	killed := false
	defer func() {
		if !killed {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}()

	helperPID, err := waitForHelperLock(stdout, 60*time.Second)
	if err != nil {
		t.Fatalf("helper did not acquire the lock: %v", err)
	}
	if helperPID == os.Getpid() {
		t.Fatalf("helper PID %d equals the parent PID — the helper did not run out-of-process", helperPID)
	}

	// The parent must be rejected while the helper holds the lock.
	l, err := output.AcquireWorkspaceLock(dir)
	if err == nil {
		_ = l.Release()
		t.Fatal("acquired a lock held by another PROCESS; the lock is not a real file lock")
	}
	if !errors.Is(err, output.ErrWorkspaceBusy) {
		t.Fatalf("cross-process acquire: want ErrWorkspaceBusy, got %v", err)
	}
	if !strings.Contains(err.Error(), strconv.Itoa(helperPID)) {
		t.Fatalf("rejection must name the holder PID %d, got %q", helperPID, err.Error())
	}

	// SIGKILL: no deferred Release runs, no cleanup of any kind. The kernel
	// drops the advisory lock when the process dies, so the next acquisition
	// must succeed — this is why no stale-lock timeout, PID liveness probe or
	// force-break flag exists.
	if err := cmd.Process.Kill(); err != nil {
		t.Fatalf("kill helper: %v", err)
	}
	killed = true
	_ = cmd.Wait()

	if _, err := os.Stat(filepath.Join(dir, output.LockFileName)); err != nil {
		t.Fatalf("a SIGKILLed holder must leave its lock FILE behind (that is the point of the test): %v", err)
	}

	after, err := output.AcquireWorkspaceLock(dir)
	if err != nil {
		t.Fatalf("acquire after SIGKILLed holder: %v — a crashed run must not brick its target", err)
	}
	if err := after.Release(); err != nil {
		t.Fatalf("release: %v", err)
	}
}

// waitForHelperLock reads the helper's stdout until it announces the lock, and
// returns the helper's PID. It fails fast rather than hanging the suite.
func waitForHelperLock(r interface{ Read([]byte) (int, error) }, timeout time.Duration) (int, error) {
	type result struct {
		pid int
		err error
	}
	ch := make(chan result, 1)
	go func() {
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if strings.HasPrefix(line, "HELPER-ERROR") {
				ch <- result{err: fmt.Errorf("helper reported: %s", line)}
				return
			}
			if strings.HasPrefix(line, "LOCKED ") {
				pid, err := strconv.Atoi(strings.TrimPrefix(line, "LOCKED "))
				ch <- result{pid: pid, err: err}
				return
			}
		}
		ch <- result{err: fmt.Errorf("helper stdout closed before announcing the lock")}
	}()

	select {
	case res := <-ch:
		return res.pid, res.err
	case <-time.After(timeout):
		return 0, fmt.Errorf("timed out after %s waiting for the helper to lock", timeout)
	}
}

func TestLockAcquireRejectsEmptyWorkspaceDir(t *testing.T) {
	l, err := output.AcquireWorkspaceLock("")
	if err == nil {
		_ = l.Release()
		t.Fatal("an empty workspaceDir must be rejected, not silently locked in the cwd")
	}
	if errors.Is(err, output.ErrWorkspaceBusy) {
		t.Fatalf("an invalid argument must not masquerade as contention: %v", err)
	}
}

func TestLockAcquireFailsOnMissingWorkspace(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-workspace")

	l, err := output.AcquireWorkspaceLock(missing)
	if err == nil {
		_ = l.Release()
		t.Fatal("locking a nonexistent workspace succeeded — the lock must never CREATE the workspace it guards")
	}
	if errors.Is(err, output.ErrWorkspaceBusy) {
		t.Fatalf("a missing workspace must not be reported as contention: %v", err)
	}
	if _, statErr := os.Stat(missing); !os.IsNotExist(statErr) {
		t.Errorf("the failed acquisition created %s", missing)
	}
}

// TestLockBusyErrorSurvivesUnreadablePayload pins the degradation contract: the
// holder's stamp is DIAGNOSTIC, so a corrupt or truncated payload must still
// produce a correct rejection — just a vaguer one. Mutual exclusion may never
// depend on parsing that file.
func TestLockBusyErrorSurvivesUnreadablePayload(t *testing.T) {
	dir := t.TempDir()

	held, err := output.AcquireWorkspaceLock(dir)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer func() { _ = held.Release() }()

	// Truncate-in-place (same inode, so the flock is untouched) and write junk.
	if err := os.WriteFile(held.Path(), []byte("{not json"), 0o644); err != nil {
		t.Fatalf("corrupt payload: %v", err)
	}

	l, err := output.AcquireWorkspaceLock(dir)
	if err == nil {
		_ = l.Release()
		t.Fatal("a corrupt payload disabled the lock — exclusion must not depend on the stamp")
	}
	if !errors.Is(err, output.ErrWorkspaceBusy) {
		t.Fatalf("want ErrWorkspaceBusy with an unreadable payload, got %v", err)
	}
}

// Internal-package tests for the atomic-write error branches that the
// behaviour tests cannot reach through the public API alone.
//
// Each test here targets a specific uncovered statement in atomic.go and
// asserts on the returned error, not on a side effect — the point is that
// the failure is SURFACED, not swallowed. Added to close the XCUT-03
// statement-weighted coverage gate for internal/core/output/atomic.go
// after 15-07 replaced the unweighted per-function mean that had been
// reporting this file above 90% while it was genuinely below.
package output

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// syncParentDir must surface an open failure rather than treating a
// missing directory as a successful no-op sync.
func TestSyncParentDirOpenErrorSurfaces(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no-such-dir")

	err := syncParentDir(missing)
	if err == nil {
		t.Fatal("syncParentDir on a missing directory returned nil; a failed open must surface")
	}
	if !strings.Contains(err.Error(), "open parent dir") {
		t.Fatalf("error should identify the failing step, got: %v", err)
	}
}

// The APFS carve-out must swallow "this device does not implement fsync"
// and nothing else. Both branches are driven through the syncFile seam:
// no portable device produces an ENOTSUP-class error and a hard I/O error
// on demand, and pinning the behaviour to whichever errno a given /dev
// node happens to return would make this gate platform-flaky.
func TestSyncParentDirSwallowsUnsupportedSync(t *testing.T) {
	dir := t.TempDir()

	for _, errno := range []syscall.Errno{syscall.ENOTSUP, syscall.EINVAL, syscall.ENODEV} {
		t.Run(errno.Error(), func(t *testing.T) {
			restore := swapSyncFile(func(*os.File) error { return errno })
			defer restore()

			if err := syncParentDir(dir); err != nil {
				t.Fatalf("errno %d must be swallowed as an unsupported dir-fsync, got: %v", uint(errno), err)
			}
		})
	}
}

// Every other fsync failure must propagate — the carve-out is not a
// blanket ignore. EIO stands in for a real device error.
func TestSyncParentDirPropagatesRealSyncError(t *testing.T) {
	dir := t.TempDir()
	restore := swapSyncFile(func(*os.File) error { return syscall.EIO })
	defer restore()

	err := syncParentDir(dir)
	if err == nil {
		t.Fatal("syncParentDir swallowed EIO; only the unsupported-device errnos may be dropped")
	}
	if !strings.Contains(err.Error(), "fsync parent dir") {
		t.Fatalf("error should identify the fsync step, got: %v", err)
	}
}

// Real directories on a working filesystem must sync without error — this
// pins that the seam and the carve-out do not mask a healthy path.
func TestSyncParentDirRealDirectorySucceeds(t *testing.T) {
	if err := syncParentDir(t.TempDir()); err != nil {
		t.Fatalf("syncParentDir on a real directory: %v", err)
	}
}

func swapSyncFile(fn func(*os.File) error) (restore func()) {
	prev := syncFile
	syncFile = fn
	return func() { syncFile = prev }
}

// WriteJSONL must fail loudly when the tempfile cannot be created. The
// target directory already exists, so MkdirAll succeeds and the failure
// lands specifically on os.CreateTemp — the branch this test pins.
func TestWriteJSONLSurfacesTempfileCreateFailure(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root: mode bits do not deny access")
	}
	dir := t.TempDir()
	readOnly := filepath.Join(dir, "readonly")
	if err := os.MkdirAll(readOnly, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Chmod(readOnly, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(readOnly, 0o755) })

	err := WriteJSONL(filepath.Join(readOnly, "out.jsonl"), [][]byte{[]byte(`{"a":1}`)})
	if err == nil {
		t.Fatal("WriteJSONL into an unwritable directory returned nil; the caller would believe the write landed")
	}
	if !strings.Contains(err.Error(), "create tempfile") {
		t.Fatalf("error should identify the tempfile step, got: %v", err)
	}
}

func swapCloseFile(fn func(*os.File) error) (restore func()) {
	prev := closeFile
	closeFile = fn
	return func() { closeFile = prev }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tempfile durability failures.
//
// The whole point of this file's write-tempfile → fsync → rename sequence is
// that a target is either the old bytes or the new ones, never a torn mix. The
// fsync- and close-failure branches are what keep that promise when the
// filesystem reports a deferred write error late — and until the syncFile /
// closeFile seams were threaded through these two functions, they were the only
// branches here that no test could reach.
//
// Each test below asserts the SAME two things, because either alone would be a
// false pass: the call reports the failure, AND it does not publish the target.
// A version that surfaced the error but had already renamed would satisfy a
// single-assertion test while having destroyed the previous artefact.
// ─────────────────────────────────────────────────────────────────────────────

func TestWriteJSONLSurfacesTempfileFsyncFailure(t *testing.T) {
	target := filepath.Join(t.TempDir(), "subdomains.jsonl")
	sentinel := errors.New("simulated deferred write error at fsync")

	restore := swapSyncFile(func(*os.File) error { return sentinel })
	defer restore()

	err := WriteJSONL(target, [][]byte{[]byte(`{"host":"a.example.com"}`)})
	if err == nil {
		t.Fatal("WriteJSONL reported success although the tempfile fsync failed — " +
			"the bytes may never have reached the device and the caller was told they had")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("error does not wrap the fsync failure: %v", err)
	}
	if _, statErr := os.Stat(target); !os.IsNotExist(statErr) {
		t.Errorf("%s exists after a failed fsync — the rename must not happen once durability is in doubt", target)
	}
}

func TestWriteJSONLSurfacesTempfileCloseFailure(t *testing.T) {
	target := filepath.Join(t.TempDir(), "hosts.jsonl")
	sentinel := errors.New("simulated deferred write error at close")

	restore := swapCloseFile(func(f *os.File) error {
		_ = f.Close() // still release the descriptor; only the verdict is simulated
		return sentinel
	})
	defer restore()

	err := WriteJSONL(target, [][]byte{[]byte(`{"host":"b.example.com"}`)})
	if err == nil {
		t.Fatal("WriteJSONL reported success although closing the tempfile failed — " +
			"on filesystems that report write errors at close this publishes a truncated artefact")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("error does not wrap the close failure: %v", err)
	}
	if _, statErr := os.Stat(target); !os.IsNotExist(statErr) {
		t.Errorf("%s exists after a failed close", target)
	}
}

func TestWriteFileSurfacesTempfileCloseFailure(t *testing.T) {
	target := filepath.Join(t.TempDir(), "report.html")
	sentinel := errors.New("simulated deferred write error at close")

	restore := swapCloseFile(func(f *os.File) error {
		_ = f.Close()
		return sentinel
	})
	defer restore()

	err := WriteFile(target, []byte("<html></html>"), 0o644)
	if err == nil {
		t.Fatal("WriteFile reported success although closing the tempfile failed")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("error does not wrap the close failure: %v", err)
	}
	if _, statErr := os.Stat(target); !os.IsNotExist(statErr) {
		t.Errorf("%s exists after a failed close", target)
	}
}

// A close failure must not destroy what was already published. This is the
// half that the "does not create the target" assertions above cannot show.
func TestFailedCloseLeavesPreviousArtefactIntact(t *testing.T) {
	target := filepath.Join(t.TempDir(), "findings.jsonl")
	const previous = `{"id":"kept"}` + "\n"
	if err := os.WriteFile(target, []byte(previous), 0o644); err != nil {
		t.Fatal(err)
	}

	restore := swapCloseFile(func(f *os.File) error {
		_ = f.Close()
		return errors.New("simulated close failure")
	})
	defer restore()

	if err := WriteJSONL(target, [][]byte{[]byte(`{"id":"new"}`)}); err == nil {
		t.Fatal("expected the close failure to be reported")
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("previous artefact disappeared: %v", err)
	}
	if string(got) != previous {
		t.Errorf("previous artefact was modified by a failed write: got %q, want %q\n"+
			"  The staging-then-rename contract exists so a failed publish is a no-op.", string(got), previous)
	}
}

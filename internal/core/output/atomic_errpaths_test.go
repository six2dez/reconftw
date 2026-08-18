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

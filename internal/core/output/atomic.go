// Package output provides reconFTW v2's atomic JSONL writer, output tree
// (workspaces/<target-id>/), scope filter, manifest writer, and compat
// symlink layer. WriteFile and WriteJSONL are the ONLY sanctioned write
// paths for files under artefacts/, reports/, inputs/, and manifest.json
// per ADR §3.5 (BINDING).
//
// Sources:
//   - ADR §3.5 lines 1333-1365 (AtomicWriter 4-step contract).
//   - spike/go/internal/output/atomic.go (reference 4-step pattern;
//     ported here, not imported — spike has its own go.mod and is hermetic
//     per Phase 1 D-03).
//   - .planning/research/PITFALLS.md §3.1 (non-atomic checkpoint writes;
//     top-5 pitfall).
//   - ROADMAP success criterion 2: "a SIGKILL injected between tempfile
//   - fsync and rename leaves the original target file intact."
package output

import (
	stderrors "errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// WriteJSONL writes each line (already-serialized JSON) to target atomically.
// Each line is followed by a single newline. The function applies the
// 4-step pattern from ADR §3.5:
//
//  1. Create a tempfile in the same directory as the target (same
//     filesystem ⇒ rename(2) is atomic, not a cross-device copy-and-delete).
//  2. Write + fsync the tempfile so data bytes are on persistent storage.
//  3. rename(2) the tempfile over the target (POSIX-atomic directory entry
//     swap; readers see either the old or new complete file, never torn).
//  4. fsync the parent directory so the directory entry update is durable
//     across a power failure (often-missed step — most third-party
//     implementations stop at 3).
//
// On macOS APFS, parent-directory fsync via os.File.Sync may return
// ENOTSUP/EINVAL for certain volume configurations. We treat those as a
// no-op: the rename itself is durable on a clean-shutdown path; only
// power-loss across the rename-vs-dirsync gap loses ordering. The
// defensive ENOTSUP handling is documented in RESEARCH.md "APFS carve-out."
//
// Production callers always pass hook=nil. The hook seam exists for
// FOUND-04 atomicity testing (writeJSONLWithHook): tests pass a hook
// that simulates a crash between the tempfile fsync and the rename.
func WriteJSONL(target string, lines [][]byte) error {
	return writeJSONLWithHook(target, lines, nil)
}

// WriteFile is the byte-blob equivalent of WriteJSONL with the same
// 4-step atomicity guarantee. Used by config snapshot (W19 migration),
// manifest writer (§3.3), and any other arbitrary-payload caller.
func WriteFile(target string, data []byte, mode os.FileMode) error {
	return writeFileWithHook(target, data, mode, nil)
}

// writeJSONLWithHook is the internal seam exposed for FOUND-04 atomicity
// tests. hook is called AFTER the tempfile is written + fsynced but
// BEFORE rename. Production callers (WriteJSONL) pass hook=nil.
//
// When hook returns a non-nil error, the function aborts without
// renaming; the tempfile is removed by the defer. The target file is
// left untouched — this is the canonical FOUND-04 guarantee.
func writeJSONLWithHook(target string, lines [][]byte, hook func(tmpName string) error) error {
	dir, base := filepath.Split(target)
	if dir == "" {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("output: mkdir %s: %w", dir, err)
	}

	// Step 1: tempfile in the same directory as the target.
	tmp, err := os.CreateTemp(dir, base+".tmp.*")
	if err != nil {
		return fmt.Errorf("output: create tempfile in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	renamed := false
	defer func() {
		if !renamed {
			_ = os.Remove(tmpName)
		}
	}()

	if err := writeJSONLLines(tmp, lines); err != nil {
		_ = tmp.Close()
		return err
	}

	// Step 2: fsync the tempfile.
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("output: fsync tempfile: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("output: close tempfile: %w", err)
	}

	// FOUND-04 hook: invoked between fsync and rename. Simulates a crash
	// at the most atomicity-critical moment.
	if hook != nil {
		if hookErr := hook(tmpName); hookErr != nil {
			return hookErr
		}
	}

	// Step 3: atomic rename.
	if err := os.Rename(tmpName, target); err != nil {
		return fmt.Errorf("output: rename %s -> %s: %w", tmpName, target, err)
	}
	renamed = true

	// Step 4: parent-directory fsync. Critical for power-loss durability;
	// gracefully degrades on APFS volumes that return ENOTSUP/EINVAL.
	return syncParentDir(dir)
}

// writeFileWithHook is the byte-blob analogue of writeJSONLWithHook. Used
// by WriteFile (production: hook=nil) and FOUND-04 byte-blob test.
func writeFileWithHook(target string, data []byte, mode os.FileMode, hook func(tmpName string) error) error {
	dir, base := filepath.Split(target)
	if dir == "" {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("output: mkdir %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, base+".tmp.*")
	if err != nil {
		return fmt.Errorf("output: create tempfile in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	renamed := false
	defer func() {
		if !renamed {
			_ = os.Remove(tmpName)
		}
	}()

	if err := writeFilePayload(tmp, data, mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("output: close tempfile: %w", err)
	}

	if hook != nil {
		if hookErr := hook(tmpName); hookErr != nil {
			return hookErr
		}
	}

	if err := os.Rename(tmpName, target); err != nil {
		return fmt.Errorf("output: rename %s -> %s: %w", tmpName, target, err)
	}
	renamed = true

	return syncParentDir(dir)
}

// writeFilePayload writes data into w, chmods, then fsyncs. Extracted so
// tests can cover the write/chmod/sync failure branches via a stub.
// The chmod/sync are no-op when w is a bytes.Buffer (test seam); when w
// is *os.File, all three operations have real effect.
func writeFilePayload(w syncableWriter, data []byte, mode os.FileMode) error {
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("output: write payload: %w", err)
	}
	if err := w.Chmod(mode); err != nil {
		return fmt.Errorf("output: chmod tempfile: %w", err)
	}
	if err := w.Sync(); err != nil {
		return fmt.Errorf("output: fsync tempfile: %w", err)
	}
	return nil
}

// syncableWriter is the subset of *os.File used by writeFilePayload —
// kept narrow so tests can stub it.
type syncableWriter interface {
	io.Writer
	Chmod(os.FileMode) error
	Sync() error
}

// syncParentDir opens dir and fsyncs it (Step 4 of the 4-step pattern).
// APFS carve-out: if Sync returns ENOTSUP or EINVAL — both are observed
// on some macOS volumes when fsyncing a directory file descriptor —
// the error is dropped silently. The rename itself is durable on a clean
// shutdown; the dir-fsync is purely a power-loss insurance step.
func syncParentDir(dir string) error {
	parent, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("output: open parent dir: %w", err)
	}
	defer parent.Close() //nolint:errcheck
	if err := parent.Sync(); err != nil {
		if isUnsupportedDirSync(err) {
			return nil
		}
		return fmt.Errorf("output: fsync parent dir: %w", err)
	}
	return nil
}

// isUnsupportedDirSync reports whether the error from fsync on a directory
// fd is one of the well-known platform "not supported" returns. APFS on
// some macOS volumes returns ENOTSUP; older filesystems return EINVAL.
func isUnsupportedDirSync(err error) bool {
	var errno syscall.Errno
	if stderrors.As(err, &errno) {
		return errno == syscall.ENOTSUP || errno == syscall.EINVAL
	}
	return false
}

// writeJSONLLines writes each line + "\n" into w. Extracted so test code
// can drive the loop with a failing io.Writer to cover the deep error
// branches (Write returning io.ErrShortWrite or similar).
func writeJSONLLines(w io.Writer, lines [][]byte) error {
	for _, line := range lines {
		if _, err := w.Write(line); err != nil {
			return fmt.Errorf("output: write line: %w", err)
		}
		if _, err := w.Write([]byte("\n")); err != nil {
			return fmt.Errorf("output: write newline: %w", err)
		}
	}
	return nil
}

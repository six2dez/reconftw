// Internal-package tests for atomic.go — exercise platform-specific paths,
// error branches, and helpers that the external behaviour tests cannot
// cover with public API alone. Folded into Task 1's coverage gate per
// XCUT-03 (critical-path ≥90%).
package output

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestIsUnsupportedDirSync exercises the platform carve-out helper.
// Covers: ENOTSUP, EINVAL, unrelated errno, non-errno error, wrapped
// ENOTSUP via fmt.Errorf("%w").
func TestIsUnsupportedDirSync(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"enotsup", syscall.ENOTSUP, true},
		{"einval", syscall.EINVAL, true},
		{"eperm", syscall.EPERM, false},
		{"non-errno", errors.New("totally generic"), false},
		{"wrapped enotsup", &os.PathError{Op: "fsync", Err: syscall.ENOTSUP}, true},
		{"wrapped einval", &os.PathError{Op: "fsync", Err: syscall.EINVAL}, true},
		{"wrapped enotdir", &os.PathError{Op: "fsync", Err: syscall.ENOTDIR}, false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isUnsupportedDirSync(tc.err); got != tc.want {
				t.Fatalf("isUnsupportedDirSync(%v) = %v; want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestSyncParentDirOpenError covers the "open parent dir failed" branch in
// syncParentDir by passing a path that cannot exist. mkdir guards against
// this in production callers but the helper itself must surface the error.
func TestSyncParentDirOpenError(t *testing.T) {
	t.Parallel()
	// A path under a non-existent parent guarantees open() fails.
	dir := filepath.Join(t.TempDir(), "no-such-dir")
	if err := syncParentDir(dir); err == nil {
		t.Fatal("expected error opening non-existent dir, got nil")
	}
}

// TestWriteJSONLEmptyDirParam exercises the dir == "" branch in
// writeJSONLWithHook. Calling with a bare base name resolves the target to
// the current working directory; we run inside t.Chdir so the test does
// not leak files into the repo.
func TestWriteJSONLEmptyDirParam(t *testing.T) {
	// Not parallel: t.Chdir is process-global.
	dir := t.TempDir()
	t.Chdir(dir)
	if err := WriteJSONL("nakedfile.jsonl", [][]byte{[]byte("x")}); err != nil {
		t.Fatalf("WriteJSONL: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "nakedfile.jsonl")); err != nil {
		t.Fatalf("Stat: %v", err)
	}
}

// TestWriteFileEmptyDirParam mirrors TestWriteJSONLEmptyDirParam for the
// byte-blob API.
func TestWriteFileEmptyDirParam(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := WriteFile("naked.toml", []byte("ok"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "naked.toml")); err != nil {
		t.Fatalf("Stat: %v", err)
	}
}

// TestWriteJSONLMkdirFails covers the MkdirAll error path: target dir is a
// path under an EXISTING REGULAR FILE — POSIX cannot create a subdir under
// a non-directory.
func TestWriteJSONLMkdirFails(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	blocker := filepath.Join(root, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatalf("seed blocker: %v", err)
	}
	target := filepath.Join(blocker, "under-a-file", "f.jsonl")
	err := WriteJSONL(target, [][]byte{[]byte("x")})
	if err == nil {
		t.Fatal("expected MkdirAll failure, got nil")
	}
}

// TestWriteFileMkdirFails — same shape for WriteFile.
func TestWriteFileMkdirFails(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	blocker := filepath.Join(root, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatalf("seed blocker: %v", err)
	}
	target := filepath.Join(blocker, "under-a-file", "f.toml")
	if err := WriteFile(target, []byte("x"), 0o644); err == nil {
		t.Fatal("expected MkdirAll failure, got nil")
	}
}

// TestWriteJSONLRenameFails covers the os.Rename error branch by making
// the target path point to a NON-EMPTY DIRECTORY. POSIX rename(2) cannot
// replace a non-empty directory with a regular file → returns ENOTEMPTY/
// EISDIR depending on platform.
func TestWriteJSONLRenameFails(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Make `dir/target.jsonl` a non-empty directory.
	target := filepath.Join(dir, "target.jsonl")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("seed dir: %v", err)
	}
	// Block the rename by putting a file inside it. POSIX rename of a regular
	// file over a non-empty directory fails (ENOTEMPTY / EEXIST / EISDIR).
	if err := os.WriteFile(filepath.Join(target, "blocker"), []byte("x"), 0o644); err != nil {
		t.Fatalf("seed blocker file: %v", err)
	}
	if err := WriteJSONL(target, [][]byte{[]byte("x")}); err == nil {
		t.Fatal("expected rename failure, got nil")
	}
	// No leftover tempfile.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if e.Name() == "target.jsonl" {
			continue
		}
		if filepath.Ext(e.Name()) != "" {
			t.Errorf("unexpected leftover: %s", e.Name())
		}
	}
}

// TestWriteFileRenameFails — same shape for WriteFile.
func TestWriteFileRenameFails(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(dir, "target.toml")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatalf("seed dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(target, "blocker"), []byte("x"), 0o644); err != nil {
		t.Fatalf("seed blocker: %v", err)
	}
	if err := WriteFile(target, []byte("x"), 0o644); err == nil {
		t.Fatal("expected rename failure, got nil")
	}
}

// TestWriteFileWithHookSuccess proves that writeFileWithHook with a nil
// error from the hook proceeds to rename + parent fsync — exercising the
// "success after hook" branch in the byte-blob path.
func TestWriteFileWithHookSuccess(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(dir, "after-hook.toml")
	called := false
	err := writeFileWithHook(target, []byte("payload"), 0o644, func(tmpName string) error {
		called = true
		// Verify the tempfile actually exists at this moment.
		if _, err := os.Stat(tmpName); err != nil {
			t.Fatalf("hook: tempfile not on disk: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("writeFileWithHook: %v", err)
	}
	if !called {
		t.Fatal("hook was not invoked")
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "payload" {
		t.Fatalf("contents = %q; want %q", got, "payload")
	}
}

// TestWriteJSONLWithHookSuccess — same for writeJSONLWithHook.
func TestWriteJSONLWithHookSuccess(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(dir, "after-hook.jsonl")
	called := false
	err := writeJSONLWithHook(target, [][]byte{[]byte("payload")}, func(tmpName string) error {
		called = true
		if _, err := os.Stat(tmpName); err != nil {
			t.Fatalf("hook: tempfile not on disk: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("writeJSONLWithHook: %v", err)
	}
	if !called {
		t.Fatal("hook was not invoked")
	}
}

// failingWriter returns errFakeWriteFailure on Nth write to exercise
// the writeJSONLLines error branches. Used to cover the deep-write
// failure paths that real OS error injection cannot easily produce.
type failingWriter struct {
	failOn int
	n      int
}

var errFakeWriteFailure = errors.New("fake write failure")

func (f *failingWriter) Write(p []byte) (int, error) {
	f.n++
	if f.n == f.failOn {
		return 0, errFakeWriteFailure
	}
	return len(p), nil
}

// TestWriteJSONLLinesFailsOnLine covers the "write line failed" branch.
func TestWriteJSONLLinesFailsOnLine(t *testing.T) {
	t.Parallel()
	err := writeJSONLLines(&failingWriter{failOn: 1}, [][]byte{[]byte(`{"x":1}`)})
	if err == nil {
		t.Fatal("expected error from failing Write on line")
	}
	if !errors.Is(err, errFakeWriteFailure) {
		t.Fatalf("expected errFakeWriteFailure wrap; got %v", err)
	}
}

// TestWriteJSONLLinesFailsOnNewline covers the "write newline failed" branch.
func TestWriteJSONLLinesFailsOnNewline(t *testing.T) {
	t.Parallel()
	err := writeJSONLLines(&failingWriter{failOn: 2}, [][]byte{[]byte(`{"x":1}`)})
	if err == nil {
		t.Fatal("expected error from failing Write on newline")
	}
	if !errors.Is(err, errFakeWriteFailure) {
		t.Fatalf("expected errFakeWriteFailure wrap; got %v", err)
	}
}

// TestWriteJSONLLinesSuccess — sanity, no-error path.
func TestWriteJSONLLinesSuccess(t *testing.T) {
	t.Parallel()
	if err := writeJSONLLines(&failingWriter{failOn: -1}, [][]byte{[]byte(`{"x":1}`)}); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
}

// stubSyncable implements syncableWriter and lets tests control each
// operation's error result. Used to cover the write/chmod/sync failure
// branches in writeFilePayload.
type stubSyncable struct {
	writeErr error
	chmodErr error
	syncErr  error
	written  []byte
}

func (s *stubSyncable) Write(p []byte) (int, error) {
	if s.writeErr != nil {
		return 0, s.writeErr
	}
	s.written = append(s.written, p...)
	return len(p), nil
}

func (s *stubSyncable) Chmod(os.FileMode) error { return s.chmodErr }
func (s *stubSyncable) Sync() error             { return s.syncErr }

// TestWriteFilePayloadWriteFails covers the write-failure branch.
func TestWriteFilePayloadWriteFails(t *testing.T) {
	t.Parallel()
	s := &stubSyncable{writeErr: errFakeWriteFailure}
	err := writeFilePayload(s, []byte("x"), 0o644)
	if err == nil || !errors.Is(err, errFakeWriteFailure) {
		t.Fatalf("expected wrapped errFakeWriteFailure; got %v", err)
	}
}

// TestWriteFilePayloadChmodFails covers the chmod-failure branch.
func TestWriteFilePayloadChmodFails(t *testing.T) {
	t.Parallel()
	wantErr := errors.New("chmod boom")
	s := &stubSyncable{chmodErr: wantErr}
	err := writeFilePayload(s, []byte("x"), 0o644)
	if err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("expected wrapped chmod error; got %v", err)
	}
}

// TestWriteFilePayloadSyncFails covers the sync-failure branch.
func TestWriteFilePayloadSyncFails(t *testing.T) {
	t.Parallel()
	wantErr := errors.New("sync boom")
	s := &stubSyncable{syncErr: wantErr}
	err := writeFilePayload(s, []byte("x"), 0o644)
	if err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("expected wrapped sync error; got %v", err)
	}
}

// TestWriteFilePayloadSuccess — sanity, no-error path.
func TestWriteFilePayloadSuccess(t *testing.T) {
	t.Parallel()
	s := &stubSyncable{}
	if err := writeFilePayload(s, []byte("hello"), 0o644); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if string(s.written) != "hello" {
		t.Fatalf("written = %q; want hello", s.written)
	}
}

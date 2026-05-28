// Source: .planning/phases/03-foundation-kernel/03-03-PLAN.md Task 1
// FOUND-04 success criterion: "a SIGKILL injected between tempfile + fsync
// and rename leaves the original target file intact."
//
// Test 7 (FOUND-04 atomicity) uses the hook simulation strategy
// (writeJSONLWithHook): production callers pass hook=nil; tests pass a hook
// that returns an error AFTER the tempfile is written but BEFORE the rename
// — semantic equivalent of SIGKILL between fsync and rename. A subprocess
// SIGKILL test is shipped under the //go:build smoke build tag in
// atomic_smoke_test.go (Ring 3 — runs on PR + scheduled per CI yaml).
package output

import (
	"bytes"
	stderrors "errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Test 1: Happy path — WriteJSONL writes newline-terminated lines into the target.
func TestAtomicWriteJSONLBasic(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(dir, "out.jsonl")
	lines := [][]byte{
		[]byte(`{"a":1}`),
		[]byte(`{"b":2}`),
	}
	if err := WriteJSONL(target, lines); err != nil {
		t.Fatalf("WriteJSONL: %v", err)
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	want := "{\"a\":1}\n{\"b\":2}\n"
	if string(data) != want {
		t.Fatalf("contents = %q; want %q", string(data), want)
	}
}

// Test 2: WriteJSONL creates the parent directory if it does not exist.
func TestAtomicWriteJSONLCreatesParentDir(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	target := filepath.Join(root, "deep", "nested", "file.jsonl")
	if err := WriteJSONL(target, [][]byte{[]byte(`{"x":1}`)}); err != nil {
		t.Fatalf("WriteJSONL: %v", err)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("Stat target: %v", err)
	}
}

// Test 3: Tempfile lives in the same directory as the target (no /tmp leak).
// Probe by hooking before rename and asserting filepath.Dir(tmpName) == dir.
func TestAtomicWriteTempfileSameDir(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(dir, "same-dir.jsonl")
	var seenTmpDir string
	err := writeJSONLWithHook(target, [][]byte{[]byte(`{}`)}, func(tmpName string) error {
		seenTmpDir = filepath.Dir(tmpName)
		return nil
	})
	if err != nil {
		t.Fatalf("writeJSONLWithHook: %v", err)
	}
	if seenTmpDir != dir {
		t.Fatalf("tmpfile dir = %q; want %q", seenTmpDir, dir)
	}
}

// Test 4: After successful write, no *.tmp.* files remain.
func TestAtomicWriteCleansupOnSuccess(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(dir, "clean.jsonl")
	if err := WriteJSONL(target, [][]byte{[]byte(`{"k":"v"}`)}); err != nil {
		t.Fatalf("WriteJSONL: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp.") {
			t.Fatalf("leftover tempfile after success: %s", e.Name())
		}
	}
}

// Test 5: If the hook errors mid-stream (simulated failure), the tempfile is
// cleaned up via defer and no *.tmp.* leftover remains.
func TestAtomicWriteCleansupOnError(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(dir, "fail.jsonl")
	wantErr := stderrors.New("simulated-failure")
	err := writeJSONLWithHook(target, [][]byte{[]byte(`{}`)}, func(_ string) error {
		return wantErr
	})
	if !stderrors.Is(err, wantErr) {
		t.Fatalf("err = %v; want simulated-failure", err)
	}
	// No tempfile should remain
	entries, err2 := os.ReadDir(dir)
	if err2 != nil {
		t.Fatalf("ReadDir: %v", err2)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp.") {
			t.Fatalf("leftover tempfile after error: %s", e.Name())
		}
	}
	// And the target was never created
	if _, statErr := os.Stat(target); !os.IsNotExist(statErr) {
		t.Fatalf("target should not exist on hook error: stat err = %v", statErr)
	}
}

// Test 6: Source assertion — parent.Sync() is called in atomic.go. Verified by
// grep in acceptance criteria; here we also do a runtime smoke: writing to a
// real directory completes without error, exercising the parent-dir fsync path.
func TestAtomicWriteParentFsyncSucceeds(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(dir, "parent.jsonl")
	if err := WriteJSONL(target, [][]byte{[]byte(`{"ok":true}`)}); err != nil {
		t.Fatalf("WriteJSONL: %v", err)
	}
}

// Test 7 — FOUND-04 (CANONICAL ATOMICITY TEST):
// Pre-populate the target with ORIGINAL content, then call writeJSONLWithHook
// passing a hook that returns an error AFTER the tempfile is written but
// BEFORE the rename. Assert the target file still contains ORIGINAL.
//
// This is the semantic equivalent of SIGKILL between fsync and rename: the
// rename never executes, so the directory entry continues to point at the
// original inode; the new tempfile is cleaned up by defer.
//
// A subprocess-based SIGKILL test (Ring 3) ships in atomic_smoke_test.go
// under the //go:build smoke tag per W12 revision iter 1 of the CI policy.
func TestFOUND04Atomicity(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(dir, "atomic.jsonl")

	// Step A: write the original.
	if err := WriteJSONL(target, [][]byte{[]byte("ORIGINAL")}); err != nil {
		t.Fatalf("seed write: %v", err)
	}
	originalBytes, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("seed read: %v", err)
	}

	// Step B: attempt a NEW write that fails AFTER tempfile but BEFORE rename.
	abort := stderrors.New("simulated-sigkill")
	err = writeJSONLWithHook(target, [][]byte{[]byte("NEW")}, func(_ string) error {
		return abort
	})
	if !stderrors.Is(err, abort) {
		t.Fatalf("expected simulated-sigkill, got %v", err)
	}

	// Step C: the original target MUST be unchanged.
	gotBytes, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("post-abort read: %v", err)
	}
	if !bytes.Equal(originalBytes, gotBytes) {
		t.Fatalf("target was modified after aborted write\noriginal: %q\nactual:   %q",
			originalBytes, gotBytes)
	}

	// Step D: tempfile was cleaned up — no *.tmp.* leftover.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp.") {
			t.Fatalf("FOUND-04: tempfile not cleaned up after aborted write: %s", e.Name())
		}
	}
}

// Test 8: WriteFile exposes the byte-blob equivalent of WriteJSONL with the
// same 4-step guarantee. Used by config snapshot + manifest writer.
func TestAtomicWriteFileBasic(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(dir, "blob.toml")
	body := []byte("[section]\nkey = \"value\"\n")
	if err := WriteFile(target, body, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("contents = %q; want %q", got, body)
	}

	// Mode honored (mask sticky/setuid bits — on macOS 0o644 is preserved).
	stat, err := os.Stat(target)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := stat.Mode().Perm(); got != 0o644 {
		t.Fatalf("mode = %v; want 0644", got)
	}
}

// Test 8b: WriteFile applies the FOUND-04 atomicity guarantee — the
// equivalent of Test 7 but for the byte-blob API. Critical because config
// snapshots flow through WriteFile (W19 migration).
func TestAtomicWriteFileFOUND04Atomicity(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(dir, "snap.toml")
	if err := WriteFile(target, []byte("ORIGINAL"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	abort := stderrors.New("simulated-sigkill")
	err := writeFileWithHook(target, []byte("NEW"), 0o644, func(_ string) error {
		return abort
	})
	if !stderrors.Is(err, abort) {
		t.Fatalf("want simulated-sigkill, got %v", err)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "ORIGINAL" {
		t.Fatalf("target modified: %q", got)
	}
}

// Test 9: Concurrent writes to DIFFERENT files succeed (no shared state).
func TestAtomicWriteConcurrentDifferentFiles(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	const N = 20
	var wg sync.WaitGroup
	wg.Add(N)
	errs := make(chan error, N)
	for i := 0; i < N; i++ {
		i := i
		go func() {
			defer wg.Done()
			target := filepath.Join(dir, fmt.Sprintf("file-%02d.jsonl", i))
			line := []byte(fmt.Sprintf(`{"i":%d}`, i))
			if err := WriteJSONL(target, [][]byte{line}); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent write error: %v", err)
	}
	// Verify every file exists with its expected content.
	for i := 0; i < N; i++ {
		target := filepath.Join(dir, fmt.Sprintf("file-%02d.jsonl", i))
		data, err := os.ReadFile(target)
		if err != nil {
			t.Errorf("ReadFile %s: %v", target, err)
			continue
		}
		want := fmt.Sprintf("{\"i\":%d}\n", i)
		if string(data) != want {
			t.Errorf("file-%02d contents = %q; want %q", i, string(data), want)
		}
	}
}

// Test 10: Concurrent writes to the SAME file produce one valid result.
// One winner; tempfiles for the losers are cleaned up; result is one of the
// inputs verbatim, never partial/corrupted.
func TestAtomicWriteConcurrentSameFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(dir, "same.jsonl")
	const N = 8
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		i := i
		go func() {
			defer wg.Done()
			line := []byte(fmt.Sprintf(`{"writer":%d}`, i))
			_ = WriteJSONL(target, [][]byte{line})
		}()
	}
	wg.Wait()
	// File must exist and content must be one of the writer payloads (+ newline)
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	gotStr := string(data)
	var matched bool
	for i := 0; i < N; i++ {
		want := fmt.Sprintf("{\"writer\":%d}\n", i)
		if gotStr == want {
			matched = true
			break
		}
	}
	if !matched {
		t.Fatalf("file contents %q does not match any concurrent writer payload", gotStr)
	}
	// No leftover tempfiles
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp.") {
			t.Fatalf("leftover tempfile after concurrent writers: %s", e.Name())
		}
	}
}

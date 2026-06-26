// batch_test.go — tests for runBatch, readTargetList, printBatchSummary (D-07/MODE-10).
package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

// TestReadTargetList verifies that blank lines and comment lines are stripped
// and non-empty targets are returned.
func TestReadTargetList(t *testing.T) {
	content := "example.com\n\n# comment\n  \ntarget.org\n"
	f := writeTempFile(t, content)

	targets, err := readTargetList(f)
	if err != nil {
		t.Fatalf("readTargetList: unexpected error: %v", err)
	}
	if len(targets) != 2 {
		t.Errorf("readTargetList: got %d targets, want 2: %v", len(targets), targets)
	}
	if targets[0] != "example.com" || targets[1] != "target.org" {
		t.Errorf("readTargetList: got %v, want [example.com target.org]", targets)
	}
}

// TestReadTargetListMissingFile verifies that a non-existent path returns an error.
func TestReadTargetListMissingFile(t *testing.T) {
	_, err := readTargetList("/nonexistent/path/targets.txt")
	if err == nil {
		t.Error("readTargetList: expected error for missing file, got nil")
	}
}

// TestReadTargetListDirectory verifies that a directory path returns an error.
func TestReadTargetListDirectory(t *testing.T) {
	dir := t.TempDir()
	_, err := readTargetList(dir)
	if err == nil {
		t.Error("readTargetList: expected error for directory path, got nil")
	}
}

// TestBatchAllSucceed verifies that runBatch returns nil error when all targets succeed.
func TestBatchAllSucceed(t *testing.T) {
	f := writeTempFile(t, "example.com\ntarget.org\n")

	called := 0
	runFn := func(_ context.Context, target string) error {
		called++
		return nil
	}

	results, err := runBatch(context.Background(), f, runFn)
	if err != nil {
		t.Errorf("TestBatchAllSucceed: expected nil error, got: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("TestBatchAllSucceed: expected 2 results, got %d", len(results))
	}
	if called != 2 {
		t.Errorf("TestBatchAllSucceed: run function called %d times, want 2", called)
	}
}

// TestBatchExitsNonZeroOnAnyFailure verifies that a single failure causes non-nil error.
func TestBatchExitsNonZeroOnAnyFailure(t *testing.T) {
	f := writeTempFile(t, "example.com\n")

	runFn := func(_ context.Context, target string) error {
		return errors.New("scan failed")
	}

	_, err := runBatch(context.Background(), f, runFn)
	if err == nil {
		t.Error("TestBatchExitsNonZeroOnAnyFailure: expected non-nil error, got nil")
	}
	if !strings.Contains(err.Error(), "1 of 1") {
		t.Errorf("TestBatchExitsNonZeroOnAnyFailure: error message %q should contain '1 of 1'", err.Error())
	}
}

// TestBatchContinuesOnError verifies that a failure in the middle target does not
// prevent the third target from being processed (D-07 continue-on-error).
func TestBatchContinuesOnError(t *testing.T) {
	f := writeTempFile(t, "first.com\nmiddle.com\nlast.com\n")

	var processed []string
	runFn := func(_ context.Context, target string) error {
		processed = append(processed, target)
		if target == "middle.com" {
			return errors.New("middle failed")
		}
		return nil
	}

	results, err := runBatch(context.Background(), f, runFn)
	if err == nil {
		t.Error("TestBatchContinuesOnError: expected non-nil aggregate error")
	}
	// All 3 targets must have been processed.
	if len(processed) != 3 {
		t.Errorf("TestBatchContinuesOnError: processed %d targets, want 3: %v", len(processed), processed)
	}
	// last.com must appear even after middle.com failed.
	if processed[2] != "last.com" {
		t.Errorf("TestBatchContinuesOnError: third processed target = %q, want 'last.com'", processed[2])
	}
	// Results slice must have 3 entries.
	if len(results) != 3 {
		t.Errorf("TestBatchContinuesOnError: results slice has %d entries, want 3", len(results))
	}
	// Middle result must carry the error.
	if results[1].Err == nil {
		t.Error("TestBatchContinuesOnError: middle result should carry an error")
	}
	// First and last results must be nil.
	if results[0].Err != nil {
		t.Errorf("TestBatchContinuesOnError: first result should be nil error, got: %v", results[0].Err)
	}
	if results[2].Err != nil {
		t.Errorf("TestBatchContinuesOnError: last result should be nil error, got: %v", results[2].Err)
	}
}

// TestPrintBatchSummary verifies that the output contains target names, statuses,
// and the "── batch summary" header.
func TestPrintBatchSummary(t *testing.T) {
	results := []batchResult{
		{Target: "ok.example.com", Err: nil},
		{Target: "fail.example.com", Err: errors.New("scan failed")},
	}
	var buf bytes.Buffer
	printBatchSummary(&buf, results)
	out := buf.String()

	if !strings.Contains(out, "batch summary") {
		t.Errorf("printBatchSummary: expected '── batch summary' header, got: %q", out)
	}
	if !strings.Contains(out, "ok.example.com") {
		t.Errorf("printBatchSummary: expected 'ok.example.com' in output, got: %q", out)
	}
	if !strings.Contains(out, "fail.example.com") {
		t.Errorf("printBatchSummary: expected 'fail.example.com' in output, got: %q", out)
	}
	if !strings.Contains(out, "OK") {
		t.Errorf("printBatchSummary: expected 'OK' status, got: %q", out)
	}
	if !strings.Contains(out, "FAIL") {
		t.Errorf("printBatchSummary: expected 'FAIL' status, got: %q", out)
	}
}

// TestBatchEmptyListReturnsNoError verifies that an empty target list
// completes with nil error and empty results.
func TestBatchEmptyListReturnsNoError(t *testing.T) {
	f := writeTempFile(t, "# only comments\n\n\n")

	results, err := runBatch(context.Background(), f, func(_ context.Context, _ string) error {
		t.Error("run function should not be called for empty list")
		return nil
	})
	if err != nil {
		t.Errorf("TestBatchEmptyListReturnsNoError: expected nil error, got: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("TestBatchEmptyListReturnsNoError: expected 0 results, got %d", len(results))
	}
}

// TestBatchMissingListFile verifies that a missing --list file returns an error
// without calling the run function.
func TestBatchMissingListFile(t *testing.T) {
	_, err := runBatch(context.Background(), "/nonexistent/targets.txt", func(_ context.Context, _ string) error {
		t.Error("run should not be called for missing file")
		return nil
	})
	if err == nil {
		t.Error("TestBatchMissingListFile: expected error for missing file, got nil")
	}
}

// writeTempFile is a test helper that writes content to a temp file and returns
// the path. The file is removed when the test finishes.
func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "targets-*.txt")
	if err != nil {
		t.Fatalf("writeTempFile: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("writeTempFile write: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("writeTempFile close: %v", err)
	}
	return f.Name()
}

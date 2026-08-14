package output_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/six2dez/reconftw/internal/core/output"
)

// TestStageJSONLRemovesOnEmpty is the F3 core: a producer that RAN and found
// nothing must clear the staging file a previous run left behind, or the merge
// republishes last run's finding as though this run had observed it.
func TestStageJSONLRemovesOnEmpty(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "findings.nuclei.jsonl")

	if err := output.StageJSONL(p, [][]byte{[]byte(`{"a":1}`)}); err != nil {
		t.Fatalf("StageJSONL(non-empty): %v", err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("staging file should exist after non-empty write: %v", err)
	}

	if err := output.StageJSONL(p, nil); err != nil {
		t.Fatalf("StageJSONL(nil): %v", err)
	}
	_, err := os.Stat(p)
	if err == nil {
		t.Fatal("staging file still present after empty StageJSONL — run B would republish run A")
	}
	if !os.IsNotExist(err) {
		t.Fatalf("expected IsNotExist, got %v", err)
	}
}

func TestStageJSONLEmptyOnMissingFileIsNoError(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "never-existed.jsonl")
	if err := output.StageJSONL(p, nil); err != nil {
		t.Fatalf("StageJSONL(nil) on absent path should be nil, got %v", err)
	}
	if err := output.StageJSONL(p, [][]byte{}); err != nil {
		t.Fatalf("StageJSONL(empty slice) on absent path should be nil, got %v", err)
	}
}

func TestStageJSONLWritesExactContent(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "findings.x.jsonl")
	lines := [][]byte{[]byte(`{"a":1}`), []byte(`{"b":2}`)}
	if err := output.StageJSONL(p, lines); err != nil {
		t.Fatalf("StageJSONL: %v", err)
	}
	// Read the full content back — the file is complete and readable, i.e. the
	// atomic temp+rename write path landed a whole file, never a torn one.
	got, err := os.ReadFile(p) //nolint:gosec // test-controlled temp path
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	want := "{\"a\":1}\n{\"b\":2}\n"
	if string(got) != want {
		t.Fatalf("content mismatch:\n got %q\nwant %q", got, want)
	}
}

func TestStageLinesWritesExactBytes(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "passive.subfinder.txt")
	if err := output.StageLines(p, []string{"a.example.com", "b.example.com"}); err != nil {
		t.Fatalf("StageLines: %v", err)
	}
	got, err := os.ReadFile(p) //nolint:gosec // test-controlled temp path
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	const want = "a.example.com\nb.example.com\n"
	if string(got) != want {
		t.Fatalf("byte-for-byte mismatch:\n got %q\nwant %q", got, want)
	}
}

// TestStageLinesBlankOnlyIsEmpty pins the blank-trim rule: []string{""} must
// CLEAR, not write a file holding one blank line that a downstream line-counter
// reports as 1 result.
func TestStageLinesBlankOnlyIsEmpty(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "resolved.puredns.txt")
	if err := output.StageLines(p, []string{"seed.example.com"}); err != nil {
		t.Fatalf("StageLines(seed): %v", err)
	}
	if err := output.StageLines(p, []string{"", "  "}); err != nil {
		t.Fatalf("StageLines(blank-only): %v", err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("blank-only input must remove the staging file, stat err = %v", err)
	}
}

func TestStageLinesRemovesOnEmpty(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "permut.gotator.txt")
	if err := output.StageLines(p, []string{"x.example.com"}); err != nil {
		t.Fatalf("StageLines: %v", err)
	}
	if err := output.StageLines(p, nil); err != nil {
		t.Fatalf("StageLines(nil): %v", err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("expected removal, stat err = %v", err)
	}
}

// TestStageParentDirCreatedOnWriteOnly: the write path creates a missing
// parent; the REMOVE path must not, because recreating a directory is a
// filesystem side effect a cleanup call has no business performing.
func TestStageParentDirCreatedOnWriteOnly(t *testing.T) {
	root := t.TempDir()

	writeParent := filepath.Join(root, "made-by-write")
	writePath := filepath.Join(writeParent, "findings.tool.jsonl")
	if err := output.StageJSONL(writePath, [][]byte{[]byte(`{"a":1}`)}); err != nil {
		t.Fatalf("StageJSONL into missing parent: %v", err)
	}
	if _, err := os.Stat(writeParent); err != nil {
		t.Fatalf("write path should have created the parent: %v", err)
	}

	removeParent := filepath.Join(root, "not-made-by-remove")
	removePath := filepath.Join(removeParent, "findings.tool.jsonl")
	if err := output.StageJSONL(removePath, nil); err != nil {
		t.Fatalf("StageJSONL(nil) into missing parent should be nil, got %v", err)
	}
	if _, err := os.Stat(removeParent); !os.IsNotExist(err) {
		t.Fatalf("remove path must NOT create the parent dir, stat err = %v", err)
	}

	lineParent := filepath.Join(root, "not-made-by-remove-lines")
	linePath := filepath.Join(lineParent, "passive.tool.txt")
	if err := output.StageLines(linePath, nil); err != nil {
		t.Fatalf("StageLines(nil) into missing parent should be nil, got %v", err)
	}
	if _, err := os.Stat(lineParent); !os.IsNotExist(err) {
		t.Fatalf("StageLines remove path must NOT create the parent dir, stat err = %v", err)
	}
}

// TestPublishArtefactEmptyCreatesZeroByteFile is the whole reason
// PublishArtefact exists: OutputTree.Append short-circuits at
// `if len(lines) == 0 { return nil }` (internal/core/output/tree.go:59-61)
// BEFORE its WriteJSONL at tree.go:105-106, so Append(stage, nil) leaves the
// previous run's artefact untouched and cannot express "this run found
// nothing".
func TestPublishArtefactEmptyCreatesZeroByteFile(t *testing.T) {
	dir := t.TempDir()

	if err := output.PublishArtefact(dir, "findings", nil); err != nil {
		t.Fatalf("PublishArtefact(nil): %v", err)
	}
	target := filepath.Join(dir, "artefacts", "findings.jsonl")
	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("empty publish must leave a PRESENT file, stat err = %v", err)
	}
	if os.IsNotExist(err) {
		t.Fatal("artefact must exist, not be absent")
	}
	if info.Size() != 0 {
		t.Fatalf("empty publish should be zero bytes, got %d", info.Size())
	}
}

func TestPublishArtefactTruncatesPreviousContent(t *testing.T) {
	dir := t.TempDir()
	one := [][]byte{[]byte(`{"host":"a.example.com"}`)}

	if err := output.PublishArtefact(dir, "findings", one); err != nil {
		t.Fatalf("PublishArtefact(one): %v", err)
	}
	target := filepath.Join(dir, "artefacts", "findings.jsonl")
	got, err := os.ReadFile(target) //nolint:gosec // test-controlled temp path
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != "{\"host\":\"a.example.com\"}\n" {
		t.Fatalf("unexpected content %q", got)
	}

	// Run B finds nothing: the artefact must become empty, not keep run A's line.
	if err := output.PublishArtefact(dir, "findings", nil); err != nil {
		t.Fatalf("PublishArtefact(nil) after content: %v", err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat after empty publish: %v", err)
	}
	if info.Size() != 0 {
		t.Fatalf("run B empty publish must truncate run A's artefact, size = %d", info.Size())
	}
}

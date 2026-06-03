// merge_multiwriter_test.go — Multi-writer integration tests for MergeAllWebArtefacts.
//
// Verifies the staging-contract fix for CR-01/CR-02:
//   - URLs from multiple producers are UNIONED (not last-writer-wins)
//   - Findings from multiple producers are UNIONED with dedup
//   - WAF records from multiple producers are UNIONED
//   - Single-writer artefacts pass through unchanged
//   - Empty glob (no staging files) is a no-op
//
// These tests are RED against pre-fix code (which never writes
// inputs/<artefact>.<tool>.jsonl staging files).  They turn GREEN after
// Tasks 2–3 apply the staging contract across all multi-writer tasks.
//
// Source: .planning/phases/05-web-pipeline-e2e/05-09-PLAN.md Task 1.
package web_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/modules/web"
)

// captureTree is an in-memory implementation of output.Interface that
// accumulates all Append calls for later assertion by the tests.
type captureTree struct {
	mu      sync.Mutex
	records map[string][][]byte // artefact name → accumulated lines across ALL calls
}

func newCaptureTree() *captureTree {
	return &captureTree{records: make(map[string][][]byte)}
}

// Append satisfies output.Interface — accumulates lines (no dedup here; dedup is
// MergeStage's responsibility).
func (c *captureTree) Append(artefact string, lines [][]byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.records[artefact] = append(c.records[artefact], lines...)
	return nil
}

// InScope satisfies output.Interface — always returns true for test simplicity.
func (c *captureTree) InScope(_ string) bool { return true }

// countUnique returns the count of unique raw JSONL lines received for artefact.
func (c *captureTree) countUnique(artefact string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	seen := make(map[string]struct{})
	for _, b := range c.records[artefact] {
		seen[string(b)] = struct{}{}
	}
	return len(seen)
}

// has returns true when the artefact has received at least one Append call.
func (c *captureTree) has(artefact string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.records[artefact]
	return ok
}

// writeJSONLFile writes records (each map[string]string is marshalled as one JSON
// line) to filepath.Join(dir, "inputs", name), creating the inputs/ subdir as
// needed. This simulates what the fixed task files write.
func writeJSONLFile(t *testing.T, dir, name string, records []map[string]string) {
	t.Helper()
	inputsDir := filepath.Join(dir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		t.Fatalf("writeJSONLFile: mkdir inputs/: %v", err)
	}
	fpath := filepath.Join(inputsDir, name)
	f, err := os.Create(fpath)
	if err != nil {
		t.Fatalf("writeJSONLFile: create %s: %v", fpath, err)
	}
	defer f.Close() //nolint:errcheck
	enc := json.NewEncoder(f)
	for _, rec := range records {
		if err := enc.Encode(rec); err != nil {
			t.Fatalf("writeJSONLFile: encode to %s: %v", fpath, err)
		}
	}
}

// makeTestApp returns an AppContext wired to workDir with the given captureTree.
func makeTestApp(workDir string, tree *captureTree) *appctx.AppContext {
	return &appctx.AppContext{
		Cfg:    &config.Config{},
		Target: &appctx.Target{WorkDir: workDir},
		Tree:   tree,
	}
}

// TestMultiWriterURLs asserts that MergeAllWebArtefacts produces the UNION of
// two URL-staging files (3 from katana + 2 from urlfinder, 0 overlap → 5 records).
//
// This test is RED before the staging-contract fix (no staging files are written).
// After Tasks 2–3 the staging files exist and the test turns GREEN.
func TestMultiWriterURLs(t *testing.T) {
	dir := t.TempDir()
	tree := newCaptureTree()
	app := makeTestApp(dir, tree)

	// Simulate katana writing inputs/urls.katana.jsonl (3 records).
	writeJSONLFile(t, dir, "urls.katana.jsonl", []map[string]string{
		{"url": "https://example.com/a", "source": "katana", "host": "example.com"},
		{"url": "https://example.com/b", "source": "katana", "host": "example.com"},
		{"url": "https://example.com/c", "source": "katana", "host": "example.com"},
	})

	// Simulate urlfinder writing inputs/urls.urlfinder.jsonl (2 distinct records).
	writeJSONLFile(t, dir, "urls.urlfinder.jsonl", []map[string]string{
		{"url": "https://example.com/d", "source": "urlfinder", "host": "example.com"},
		{"url": "https://example.com/e", "source": "urlfinder", "host": "example.com"},
	})

	if err := web.MergeAllWebArtefacts(context.Background(), app); err != nil {
		t.Fatalf("MergeAllWebArtefacts: unexpected error: %v", err)
	}

	// Expect 5 unique records (union of both staging files).
	got := tree.countUnique("urls")
	if got != 5 {
		t.Errorf("TestMultiWriterURLs: expected 5 deduplicated URL records, got %d", got)
	}
}

// TestMultiWriterFindings asserts UNION with 1 overlapping record:
// nuclei (3 records) + nomore403 (2 records, 1 exact-copy overlap) → 4 unique.
func TestMultiWriterFindings(t *testing.T) {
	dir := t.TempDir()
	tree := newCaptureTree()
	app := makeTestApp(dir, tree)

	// Shared record (appears in both staging files — should count once).
	overlap := map[string]string{
		"type":       "http",
		"host":       "example.com",
		"template_id": "iis-version",
		"severity":   "info",
		"confidence": "high",
	}

	writeJSONLFile(t, dir, "findings.nuclei.jsonl", []map[string]string{
		overlap,
		{"type": "nuclei-finding", "host": "a.example.com", "severity": "low", "confidence": "high"},
		{"type": "nuclei-finding", "host": "b.example.com", "severity": "medium", "confidence": "high"},
	})

	writeJSONLFile(t, dir, "findings.nomore403.jsonl", []map[string]string{
		overlap, // exact duplicate of the record above
		{"type": "http", "host": "c.example.com", "severity": "medium", "confidence": "medium"},
	})

	if err := web.MergeAllWebArtefacts(context.Background(), app); err != nil {
		t.Fatalf("MergeAllWebArtefacts: unexpected error: %v", err)
	}

	// 3 nuclei + 2 nomore403 - 1 duplicate = 4 unique records.
	got := tree.countUnique("findings")
	if got != 4 {
		t.Errorf("TestMultiWriterFindings: expected 4 deduplicated findings records, got %d", got)
	}
}

// TestMultiWriterWAF asserts UNION of wafw00f (2 records) + cdncheck (1 record) = 3.
func TestMultiWriterWAF(t *testing.T) {
	dir := t.TempDir()
	tree := newCaptureTree()
	app := makeTestApp(dir, tree)

	writeJSONLFile(t, dir, "waf.wafw00f.jsonl", []map[string]string{
		{"host": "https://api.example.com", "waf": "Cloudflare", "cdn": "", "detected_by": "wafw00f"},
		{"host": "https://www.example.com", "waf": "Akamai", "cdn": "", "detected_by": "wafw00f"},
	})

	writeJSONLFile(t, dir, "waf.cdncheck.jsonl", []map[string]string{
		{"host": "https://assets.example.com", "waf": "", "cdn": "Fastly", "detected_by": "cdncheck"},
	})

	if err := web.MergeAllWebArtefacts(context.Background(), app); err != nil {
		t.Fatalf("MergeAllWebArtefacts: unexpected error: %v", err)
	}

	got := tree.countUnique("waf")
	if got != 3 {
		t.Errorf("TestMultiWriterWAF: expected 3 WAF records (2 wafw00f + 1 cdncheck), got %d", got)
	}
}

// TestMergeStage_SingleWriter_NotAffected asserts that a single-writer artefact
// (e.g. hosts.httpx.jsonl) passes through MergeAllWebArtefacts unchanged.
func TestMergeStage_SingleWriter_NotAffected(t *testing.T) {
	dir := t.TempDir()
	tree := newCaptureTree()
	app := makeTestApp(dir, tree)

	writeJSONLFile(t, dir, "hosts.httpx.jsonl", []map[string]string{
		{"host": "example.com", "url": "https://example.com", "status": "200"},
		{"host": "api.example.com", "url": "https://api.example.com", "status": "200"},
		{"host": "www.example.com", "url": "https://www.example.com", "status": "301"},
	})

	if err := web.MergeAllWebArtefacts(context.Background(), app); err != nil {
		t.Fatalf("MergeAllWebArtefacts: unexpected error: %v", err)
	}

	got := tree.countUnique("hosts")
	if got != 3 {
		t.Errorf("TestMergeStage_SingleWriter_NotAffected: expected 3 host records, got %d", got)
	}
}

// TestMergeStage_EmptyGlob_NoOp asserts that MergeAllWebArtefacts is a no-op when
// no staging files exist for a given prefix (no Append call is made).
func TestMergeStage_EmptyGlob_NoOp(t *testing.T) {
	dir := t.TempDir()
	// Ensure inputs/ exists but has NO files with the "fuzz" prefix.
	if err := os.MkdirAll(filepath.Join(dir, "inputs"), 0o755); err != nil {
		t.Fatalf("mkdir inputs/: %v", err)
	}

	tree := newCaptureTree()
	app := makeTestApp(dir, tree)

	if err := web.MergeAllWebArtefacts(context.Background(), app); err != nil {
		t.Fatalf("MergeAllWebArtefacts on empty dir: unexpected error: %v", err)
	}

	// No Append calls should have been made for any prefix.
	if tree.has("fuzz") {
		t.Errorf("TestMergeStage_EmptyGlob_NoOp: expected no Append for 'fuzz' but got records")
	}
	if tree.has("urls") {
		t.Errorf("TestMergeStage_EmptyGlob_NoOp: expected no Append for 'urls' but got records")
	}
	if tree.has("findings") {
		t.Errorf("TestMergeStage_EmptyGlob_NoOp: expected no Append for 'findings' but got records")
	}
}

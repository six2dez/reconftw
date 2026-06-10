// Source: .planning/phases/03-foundation-kernel/03-03-PLAN.md Task 2 (OutputTree).
// Test 4 is the canonical scope-filter-at-write-boundary gate.
package output_test

import (
	"bytes"
	"encoding/json"
	stderrors "errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
	"github.com/six2dez/reconftw/internal/core/output"
)

func newTestTree(t *testing.T) *output.OutputTree {
	t.Helper()
	dir := t.TempDir()
	root := filepath.Join(dir, "workspace")
	tree, err := output.NewTree(root, &output.DefaultScopeFilter{Patterns: []string{"*.example.com"}})
	if err != nil {
		t.Fatalf("NewTree: %v", err)
	}
	return tree
}

// Test 1: NewTree creates the workspace directory structure.
func TestOutputTreeCreatesSubdirs(t *testing.T) {
	t.Parallel()
	tree := newTestTree(t)
	for _, sub := range []string{"inputs", "artefacts", "raw", "reports", "logs"} {
		path := filepath.Join(tree.Root, sub)
		stat, err := os.Stat(path)
		if err != nil {
			t.Fatalf("Stat %s: %v", path, err)
		}
		if !stat.IsDir() {
			t.Fatalf("%s is not a dir", path)
		}
	}
}

// Test 2: Append writes lines to artefacts/<name>.jsonl via atomic.
func TestOutputTreeAppendWritesJSONL(t *testing.T) {
	t.Parallel()
	tree := newTestTree(t)
	lines := [][]byte{
		[]byte(`{"subdomain":"api.example.com","source":"subfinder"}`),
		[]byte(`{"subdomain":"www.example.com","source":"crt"}`),
	}
	if err := tree.Append("subdomains", lines); err != nil {
		t.Fatalf("Append: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(tree.Root, "artefacts", "subdomains.jsonl"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	got := strings.TrimRight(string(body), "\n")
	want := `{"subdomain":"api.example.com","source":"subfinder"}` + "\n" +
		`{"subdomain":"www.example.com","source":"crt"}`
	if got != want {
		t.Fatalf("contents = %q; want %q", got, want)
	}
}

// Test 3: Append REPLACES — full content of `lines` overwrites the existing
// file. ADR §3.2 dedup is owned by the caller (Phase 4-7 tasks dedup
// before calling Append); the canonical write semantic at the OutputTree
// boundary is REPLACE.
func TestOutputTreeAppendReplaces(t *testing.T) {
	t.Parallel()
	tree := newTestTree(t)

	first := [][]byte{
		[]byte(`{"subdomain":"a.example.com","source":"x"}`),
	}
	if err := tree.Append("subdomains", first); err != nil {
		t.Fatalf("first Append: %v", err)
	}

	second := [][]byte{
		[]byte(`{"subdomain":"b.example.com","source":"y"}`),
		[]byte(`{"subdomain":"c.example.com","source":"z"}`),
	}
	if err := tree.Append("subdomains", second); err != nil {
		t.Fatalf("second Append: %v", err)
	}

	body, err := os.ReadFile(filepath.Join(tree.Root, "artefacts", "subdomains.jsonl"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if strings.Contains(string(body), "a.example.com") {
		t.Fatal("second Append did not REPLACE first (REPLACE semantics required)")
	}
	if !strings.Contains(string(body), "b.example.com") || !strings.Contains(string(body), "c.example.com") {
		t.Fatalf("contents missing second-batch lines: %s", body)
	}
}

// Test 4 — CANONICAL FOUND-04 SCOPE GATE:
// If any line is out-of-scope, the WHOLE batch is rejected, the typed
// *OutOfScope error is returned, and the existing file is untouched.
func TestOutputTreeRejectsOutOfScope(t *testing.T) {
	t.Parallel()
	tree := newTestTree(t)

	// Seed the file with a valid batch first.
	good := [][]byte{[]byte(`{"subdomain":"first.example.com","source":"x"}`)}
	if err := tree.Append("subdomains", good); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Now attempt a batch that includes an out-of-scope value.
	mixed := [][]byte{
		[]byte(`{"subdomain":"valid.example.com","source":"x"}`),
		[]byte(`{"subdomain":"evil.com","source":"x"}`),
	}
	err := tree.Append("subdomains", mixed)
	if err == nil {
		t.Fatal("expected *OutOfScope error, got nil")
	}
	var oos *coreerrors.OutOfScope
	if !stderrors.As(err, &oos) {
		t.Fatalf("expected *OutOfScope, got %T: %v", err, err)
	}
	if oos.Value != "evil.com" {
		t.Errorf("OutOfScope.Value = %q; want %q", oos.Value, "evil.com")
	}

	// Sentinel check on errors.Is — must traverse to ErrScope.
	if !stderrors.Is(err, coreerrors.ErrScope) {
		t.Fatal("errors.Is(err, ErrScope) must be true for *OutOfScope")
	}

	// The original content must still be on disk (no partial write).
	body, readErr := os.ReadFile(filepath.Join(tree.Root, "artefacts", "subdomains.jsonl"))
	if readErr != nil {
		t.Fatalf("ReadFile: %v", readErr)
	}
	if !strings.Contains(string(body), "first.example.com") {
		t.Fatalf("scope-rejected batch overwrote original: %s", body)
	}
	if strings.Contains(string(body), "evil.com") {
		t.Fatal("out-of-scope value was written")
	}
}

// Test 5: Append to a NEW artefact name creates the JSONL file.
func TestOutputTreeAppendCreatesNewArtefact(t *testing.T) {
	t.Parallel()
	tree := newTestTree(t)
	lines := [][]byte{[]byte(`{"note":"hello","tags":["hotlist"]}`)}
	if err := tree.Append("notes", lines); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tree.Root, "artefacts", "notes.jsonl")); err != nil {
		t.Fatalf("notes.jsonl not created: %v", err)
	}
}

// Pass-through artefact (no scope check): notes.jsonl, asns.jsonl.
func TestOutputTreeUnsupervisedArtefactPassesThrough(t *testing.T) {
	t.Parallel()
	tree := newTestTree(t)
	// Notes don't have a host/subdomain field, but they're shapeless arbitrary JSON.
	lines := [][]byte{[]byte(`{"note":"manual finding","tags":["hotlist"]}`)}
	if err := tree.Append("notes", lines); err != nil {
		t.Fatalf("Append: %v", err)
	}
}

// hosts.jsonl uses the `host` field per ADR §3.2.
func TestOutputTreeHostsArtefactScopeCheck(t *testing.T) {
	t.Parallel()
	tree := newTestTree(t)
	good := [][]byte{[]byte(`{"host":"alive.example.com","ip":"1.2.3.4"}`)}
	if err := tree.Append("hosts", good); err != nil {
		t.Fatalf("Append in-scope hosts: %v", err)
	}
	bad := [][]byte{[]byte(`{"host":"phisher.org","ip":"1.1.1.1"}`)}
	err := tree.Append("hosts", bad)
	if err == nil {
		t.Fatal("expected OutOfScope for hosts.jsonl out-of-scope host")
	}
}

// urls.jsonl uses the `url` field — scope check on the URL's host.
func TestOutputTreeURLsArtefactScopeCheck(t *testing.T) {
	t.Parallel()
	tree := newTestTree(t)
	good := [][]byte{[]byte(`{"url":"https://api.example.com/path","status":200}`)}
	if err := tree.Append("urls", good); err != nil {
		t.Fatalf("Append in-scope urls: %v", err)
	}
	bad := [][]byte{[]byte(`{"url":"https://evil.com/page","status":200}`)}
	if err := tree.Append("urls", bad); err == nil {
		t.Fatal("expected OutOfScope for urls out-of-scope")
	}
}

// findings.jsonl prefers host but falls back to url field.
func TestOutputTreeFindingsScopeCheck(t *testing.T) {
	t.Parallel()
	tree := newTestTree(t)
	good := [][]byte{[]byte(`{"rule_id":"x","host":"api.example.com","severity":"high"}`)}
	if err := tree.Append("findings", good); err != nil {
		t.Fatalf("findings in-scope: %v", err)
	}
	bad := [][]byte{[]byte(`{"rule_id":"x","url":"https://nope.org/","severity":"low"}`)}
	if err := tree.Append("findings", bad); err == nil {
		t.Fatal("expected OutOfScope on out-of-scope finding")
	}
}

// Company-seeded OSINT findings (D-O1) carry class=="osint" and NEITHER host
// NOR url (whois, leaked-secret, postman-leak, misconfig, asn, …). They must be
// ADMITTED without a per-host scope check — the record is bounded by the company
// seed. A non-osint finding lacking host+url must STILL be rejected (strict gate
// preserved). Regression for the Phase 7 DoD-2 merge failure where the osint
// findings.jsonl was silently emptied by the missing-field rejection.
func TestOutputTreeFindingsOSINTNoHostURLAdmitted(t *testing.T) {
	t.Parallel()
	tree := newTestTree(t)

	// class=="osint", no host/url → admitted.
	osintRecs := [][]byte{
		[]byte(`{"class":"osint","source":"domain_info","category":"whois","severity":"informational"}`),
		[]byte(`{"class":"osint","source":"postman","category":"postman-leak","value_redacted":"***"}`),
	}
	if err := tree.Append("findings", osintRecs); err != nil {
		t.Fatalf("company-seeded osint findings (no host/url) must be admitted: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(tree.Root, "artefacts", "findings.jsonl"))
	if err != nil {
		t.Fatalf("read findings.jsonl: %v", err)
	}
	if !bytes.Contains(body, []byte(`"source":"domain_info"`)) ||
		!bytes.Contains(body, []byte(`"source":"postman"`)) {
		t.Fatalf("osint findings not written: %s", body)
	}

	// A NON-osint finding with no host/url is still rejected (strict gate intact).
	nonOsint := [][]byte{[]byte(`{"rule_id":"x","severity":"high"}`)}
	if err := tree.Append("findings", nonOsint); err == nil {
		t.Fatal("non-osint finding lacking host+url must still be rejected")
	}
}

// Empty batch — no-op, no error.
func TestOutputTreeAppendEmptyBatch(t *testing.T) {
	t.Parallel()
	tree := newTestTree(t)
	if err := tree.Append("subdomains", nil); err != nil {
		t.Fatalf("empty batch: %v", err)
	}
}

// Malformed JSON line — Append must surface an error and NOT write.
func TestOutputTreeRejectsMalformedJSON(t *testing.T) {
	t.Parallel()
	tree := newTestTree(t)
	bad := [][]byte{[]byte("not-json")}
	err := tree.Append("subdomains", bad)
	if err == nil {
		t.Fatal("expected error on malformed JSON")
	}
	// File must not exist.
	if _, err := os.Stat(filepath.Join(tree.Root, "artefacts", "subdomains.jsonl")); !os.IsNotExist(err) {
		t.Fatalf("artefact should not exist after malformed write: stat err = %v", err)
	}
}

// Test 14: WorkspaceInit creates the workspace dir with the sanitized
// target slug and a timestamp.
func TestWorkspaceInit(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	ws, err := output.WorkspaceInit(root, "hackerone.com")
	if err != nil {
		t.Fatalf("WorkspaceInit: %v", err)
	}
	if !strings.Contains(ws, "hackerone_com") && !strings.Contains(ws, "hackerone.com") {
		t.Fatalf("workspace path does not include sanitized target: %s", ws)
	}
	if !strings.HasPrefix(ws, root) {
		t.Fatalf("workspace not under root: %s vs %s", ws, root)
	}
	for _, sub := range []string{"inputs", "artefacts", "raw", "reports", "logs"} {
		if _, err := os.Stat(filepath.Join(ws, sub)); err != nil {
			t.Fatalf("subdir %s missing: %v", sub, err)
		}
	}
}

// Sanitization: shell metacharacters in target are stripped.
func TestWorkspaceInitSanitizesTarget(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	ws, err := output.WorkspaceInit(root, "foo;rm -rf /")
	if err != nil {
		t.Fatalf("WorkspaceInit: %v", err)
	}
	if strings.ContainsAny(filepath.Base(ws), ";& |") {
		t.Fatalf("workspace name contains metacharacters: %s", ws)
	}
}

// Sanity round-trip: Append after WorkspaceInit lands the data where we
// expect.
func TestWorkspaceInitAndAppend(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	ws, err := output.WorkspaceInit(root, "example.com")
	if err != nil {
		t.Fatalf("WorkspaceInit: %v", err)
	}
	tree, err := output.NewTree(ws, &output.DefaultScopeFilter{Patterns: []string{"*.example.com", "example.com"}})
	if err != nil {
		t.Fatalf("NewTree: %v", err)
	}
	line := mustJSON(t, map[string]any{"subdomain": "x.example.com", "source": "test"})
	if err := tree.Append("subdomains", [][]byte{line}); err != nil {
		t.Fatalf("Append: %v", err)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return b
}

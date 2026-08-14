// filter_test.go — FilterInScope must accept exactly what Append accepts.
//
// The whole point of this helper is that it is NOT a hand-rolled mirror of the
// gate. These tests pin that equivalence: for every case, the filter's verdict
// and Append's verdict must agree. If they ever diverge — filter looser and
// Append still rejects the batch, filter stricter and good records vanish —
// TestFilterInScopeAgreesWithAppend fails.
package output_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/six2dez/reconftw/internal/core/output"
)

func newFilterTree(t *testing.T) *output.OutputTree {
	t.Helper()
	tree, err := output.NewTree(t.TempDir(), &output.DefaultScopeFilter{
		Patterns: []string{"example.com", "*.example.com"},
	})
	if err != nil {
		t.Fatalf("NewTree: %v", err)
	}
	return tree
}

func TestFilterInScope(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		artefact string
		line     string
		wantKept bool
	}{
		{"findings in-scope host", "findings", `{"host":"api.example.com","severity":"high"}`, true},
		{"findings out-of-scope host", "findings", `{"host":"evil.org","severity":"high"}`, false},
		{"findings no locator", "findings", `{"severity":"critical","vuln_class":"sqli"}`, false},
		{"findings url fallback", "findings", `{"url":"https://api.example.com/x","severity":"low"}`, true},
		{"findings url out of scope", "findings", `{"url":"https://evil.org/x"}`, false},
		{"findings url with userinfo", "findings", `{"url":"https://u:p@api.example.com/x"}`, false},
		{"osint exemption kept", "findings", `{"class":"osint","source":"whois"}`, true},
		{"osint tag but out-of-scope host", "findings", `{"class":"osint","host":"evil.org"}`, false},
		{"subdomains in scope", "subdomains", `{"subdomain":"a.example.com"}`, true},
		{"subdomains out of scope", "subdomains", `{"subdomain":"a.evil.org"}`, false},
		{"hosts in scope", "hosts", `{"host":"api.example.com"}`, true},
		{"urls in scope", "urls", `{"url":"https://api.example.com/a"}`, true},
		{"urls junk fragment", "urls", `{"url":".json"}`, false},
		{"pass-through artefact", "notes", `{"anything":"goes"}`, true},
		{"pass-through invalid json", "notes", `not json`, false},
		{"invalid json scoped", "findings", `{"host":`, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tree := newFilterTree(t)
			kept, dropped := output.FilterInScope(tree, tc.artefact, [][]byte{[]byte(tc.line)})
			if tc.wantKept && (len(kept) != 1 || dropped != 0) {
				t.Fatalf("want kept, got kept=%d dropped=%d", len(kept), dropped)
			}
			if !tc.wantKept && (len(kept) != 0 || dropped != 1) {
				t.Fatalf("want dropped, got kept=%d dropped=%d", len(kept), dropped)
			}
		})
	}
}

// TestFilterInScopeAgreesWithAppend is the equivalence guard. Every line the
// filter keeps must be accepted by Append, and every line it drops must be
// rejected — checked against the real gate, one line at a time.
func TestFilterInScopeAgreesWithAppend(t *testing.T) {
	t.Parallel()

	lines := []string{
		`{"host":"api.example.com","severity":"high"}`,
		`{"host":"evil.org","severity":"high"}`,
		`{"severity":"critical","vuln_class":"sqli"}`,
		`{"url":"https://api.example.com/x"}`,
		`{"url":"https://u:p@api.example.com/x"}`,
		`{"class":"osint","source":"whois"}`,
		`{"host":"","url":""}`,
	}

	for _, raw := range lines {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()
			batch := [][]byte{[]byte(raw)}

			filterKeeps := func() bool {
				kept, _ := output.FilterInScope(newFilterTree(t), "findings", batch)
				return len(kept) == 1
			}()

			appendAccepts := func() bool {
				return newFilterTree(t).Append("findings", batch) == nil
			}()

			if filterKeeps != appendAccepts {
				t.Errorf("filter/Append disagree on %s: filter keeps=%v, Append accepts=%v",
					raw, filterKeeps, appendAccepts)
			}
		})
	}
}

// TestFilterInScopeRescuesBatch is the failure mode the helper exists for: one
// unusable record must not take the good ones down with it.
func TestFilterInScopeRescuesBatch(t *testing.T) {
	t.Parallel()
	tree := newFilterTree(t)

	batch := [][]byte{
		[]byte(`{"host":"api.example.com","vuln_class":"websocket"}`),
		[]byte(`{"severity":"critical","vuln_class":"sqli"}`), // no locator
		[]byte(`{"host":"www.example.com","vuln_class":"xss"}`),
	}

	// Unfiltered, the strict gate rejects everything.
	if err := tree.Append("findings", batch); err == nil {
		t.Fatal("expected Append to reject the raw batch — the gate is the premise here")
	}
	if _, err := readArtefact(tree, "findings"); err == nil {
		t.Fatal("rejected batch must not have written findings.jsonl")
	}

	// Filtered, the two good records survive.
	kept, dropped := output.FilterInScope(tree, "findings", batch)
	if len(kept) != 2 || dropped != 1 {
		t.Fatalf("want 2 kept / 1 dropped, got %d / %d", len(kept), dropped)
	}
	if err := tree.Append("findings", kept); err != nil {
		t.Fatalf("filtered batch must be accepted: %v", err)
	}
}

func readArtefact(tree *output.OutputTree, name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(tree.Root, "artefacts", name+".jsonl"))
}

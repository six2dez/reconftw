// urldedup_scope_test.go — regression guard for the URL data-loss bug.
//
// Live symptom (reconbox3, all-mode):
//
//	web.urldedup: Tree.Append(urls) failed — final urls.jsonl not written
//	  records=1108 err="out of scope: .json (not in workspace scope (urls))"
//
// A single junk entry — a bare ".json" fragment emitted by a URL extractor —
// made OutputTree.Append reject the WHOLE batch, so 1108 good URLs were never
// written and every downstream URL consumer (vulns smuggling/second_order/
// webcache/ssrf/fray/llm/websocket, arjun) got nothing.
//
// Append is strict on purpose: it is the scope-enforcement boundary for
// single-source Task writes, and the Scheduler deliberately does not swallow
// OutOfScope. output.Interface documents the division of labour — MULTI-SOURCE
// aggregators must drop noise with InScope BEFORE calling Append. urldedup globs
// every inputs/urls.*.jsonl producer, so it is an aggregator and must filter.
//
// These tests run against a REAL *output.OutputTree with a REAL scope filter, so
// they exercise the actual Append strictness rather than a permissive mock.
package web_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/modules/web"
)

// newScopedURLDedupApp builds an AppContext whose Tree is a real OutputTree scoped
// to example.com, with a staging file containing the given raw url field values.
func newScopedURLDedupApp(t *testing.T, urls []string) (*appctx.AppContext, string) {
	t.Helper()
	workDir := t.TempDir()

	tree, err := output.NewTree(workDir, &output.DefaultScopeFilter{
		Patterns: []string{"example.com", "*.example.com"},
	})
	if err != nil {
		t.Fatalf("NewTree: %v", err)
	}

	var sb strings.Builder
	for _, u := range urls {
		line, merr := json.Marshal(map[string]string{"url": u, "source": "katana"})
		if merr != nil {
			t.Fatalf("marshal: %v", merr)
		}
		sb.Write(line)
		sb.WriteByte('\n')
	}
	stage := filepath.Join(workDir, "inputs", "urls.katana.jsonl")
	if werr := os.WriteFile(stage, []byte(sb.String()), 0o644); werr != nil {
		t.Fatalf("write staging: %v", werr)
	}

	cfg := config.Defaults()
	app := &appctx.AppContext{
		Cfg:    cfg,
		Tree:   tree,
		Tools:  backend.NewRunner(backend.NewLocalBackend(0), backend.NewToolRegistry(), nil),
		Target: &appctx.Target{Domain: "example.com", WorkDir: workDir},
	}
	return app, workDir
}

// readURLArtefact returns the url field of every record in artefacts/urls.jsonl.
func readURLArtefact(t *testing.T, workDir string) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(workDir, "artefacts", "urls.jsonl"))
	if err != nil {
		return nil // absent == nothing written
	}
	var got []string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var rec map[string]any
		if uerr := json.Unmarshal([]byte(line), &rec); uerr != nil {
			t.Fatalf("artefact line is not JSON: %s", line)
		}
		if u, ok := rec["url"].(string); ok {
			got = append(got, u)
		}
	}
	return got
}

// One junk record must not cost the whole harvest.
func TestUrlDedupDropsJunkInsteadOfLosingBatch(t *testing.T) {
	app, workDir := newScopedURLDedupApp(t, []string{
		"https://api.example.com/v1/users",
		".json", // the exact live junk value
		"https://www.example.com/login",
	})

	res, err := (&web.UrlDedupTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("Run returned error %v (status %v)\n"+
			"(one malformed URL rejected the whole batch and urls.jsonl was never written)",
			err, res.Status)
	}

	got := readURLArtefact(t, workDir)
	if len(got) != 2 {
		t.Fatalf("urls.jsonl has %d records %v, want the 2 in-scope URLs", len(got), got)
	}
	for _, u := range got {
		if u == ".json" {
			t.Errorf("junk record was written to the artefact: %q", u)
		}
	}
}

// Out-of-scope hosts and credential-bearing URLs are dropped for the same reason:
// Append would reject them (userinfo is rejected unconditionally, SUBD-05), taking
// every legitimate URL down with them.
func TestUrlDedupDropsOutOfScopeAndUserinfoURLs(t *testing.T) {
	app, workDir := newScopedURLDedupApp(t, []string{
		"https://api.example.com/ok",
		"https://evil.attacker.com/steal",      // out of scope
		"https://user:pass@api.example.com/x",  // userinfo → Append rejects
		"https://examplecom.evil.org/anchored", // anchored-suffix false positive
	})

	if _, err := (&web.UrlDedupTask{}).Run(context.Background(), app); err != nil {
		t.Fatalf("Run: %v", err)
	}

	got := readURLArtefact(t, workDir)
	if len(got) != 1 || got[0] != "https://api.example.com/ok" {
		t.Errorf("urls.jsonl = %v, want only the single in-scope credential-free URL", got)
	}
}

// If every URL is junk there is nothing to write — and the task must still succeed
// rather than reporting a failure the stage loop would log as a web-pipeline error.
func TestUrlDedupAllJunkIsNotAnError(t *testing.T) {
	app, workDir := newScopedURLDedupApp(t, []string{".json", "https://evil.attacker.com/x"})

	if _, err := (&web.UrlDedupTask{}).Run(context.Background(), app); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := readURLArtefact(t, workDir); len(got) != 0 {
		t.Errorf("urls.jsonl = %v, want nothing written", got)
	}
}

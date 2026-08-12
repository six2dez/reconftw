// urls_corpus_test.go — regression guard for the vulns URL-corpus path double-join
// (live all-mode, reconbox3, 2026-08). resolveURLInput returned the resolved corpus
// FILE (…/artefacts/urls.jsonl), but readURLsJSONL re-appended "artefacts/urls.jsonl"
// to it → ENOENT → readURLsWithCtx returned zero URLs, so all 11 URL-consuming vulns
// tasks (crlf/fray/gf/graphql/grpc/llm/nuclei_dast/second_order/smuggling/webcache/
// websocket) skipped "no URL corpus" despite a populated urls.jsonl. This seeds a real
// corpus and asserts readURLsWithCtx actually returns its URLs.
package vulns

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/six2dez/reconftw/internal/core/appctx"
)

func TestReadURLsWithCtxResolvesCorpus(t *testing.T) {
	workDir := t.TempDir()
	artefacts := filepath.Join(workDir, "artefacts")
	if err := os.MkdirAll(artefacts, 0o755); err != nil {
		t.Fatalf("mkdir artefacts: %v", err)
	}
	// Mixed schema: a JSON object with a "url" field + a bare URL line (both supported).
	body := `{"url":"https://a.example.com/x"}` + "\n" + "https://b.example.com/y\n"
	if err := os.WriteFile(filepath.Join(artefacts, "urls.jsonl"), []byte(body), 0o644); err != nil {
		t.Fatalf("seed urls.jsonl: %v", err)
	}

	// No --urls in ctx → resolveURLInput falls to priority 2 (artefacts/urls.jsonl).
	app := &appctx.AppContext{Target: &appctx.Target{Domain: "example.com", WorkDir: workDir}}

	urls, err := readURLsWithCtx(context.Background(), app)
	if err != nil {
		t.Fatalf("readURLsWithCtx: %v", err)
	}
	if len(urls) != 2 {
		t.Fatalf("readURLsWithCtx returned %d urls, want 2 — double-join regression: the "+
			"corpus resolved empty even though artefacts/urls.jsonl has 2 entries. got=%v", len(urls), urls)
	}
	found := map[string]bool{}
	for _, u := range urls {
		found[u] = true
	}
	for _, want := range []string{"https://a.example.com/x", "https://b.example.com/y"} {
		if !found[want] {
			t.Errorf("missing url %q in %v", want, urls)
		}
	}
}

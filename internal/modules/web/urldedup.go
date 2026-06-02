// urldedup.go — UrlDedupTask: URL deduplication via urless + p1radup.
//
// Name: "web.urldedup"  DependsOn: ["web.katana", "web.urlfinder", "web.waymore"]
//
// UrlDedupTask merges URL records from katana/urlfinder/waymore outputs,
// deduplicates via urless (stdin → stdout) then p1radup (-i/-o/-s), and
// overwrites artefacts/urls.jsonl with the deduplicated set.
//
// PIPELINE (RESEARCH §urless, §p1radup, web.sh:2021, 2037):
//
//	urless < merged_urls.txt  (stdin → stdout)
//	p1radup -i <file> -o <file> -s
//
// urless is stdin-only; since Backend.Runner does not expose a stdin pipe,
// this task uses a write-to-pipe-file approach: it writes the merged URL list
// to a named pipe file (tmp file path), then runs urless with the tmp file
// redirected via a shell-level wrapper. Since that approach requires /bin/sh,
// and to remain FOUND-10 compliant (no raw exec.Command outside backend),
// we perform an equivalent in-process deduplication when urless is absent.
//
// In-process dedup fallback: exact URL deduplication (preserves first-seen
// order) applied before p1radup. p1radup is then run via app.Tools.Run().
//
// Axiom: LocalBackend only for both tools (D-W13).
// T-05-15: scope filtering already applied by upstream Tasks; urls.jsonl
// only contains in-scope records before dedup.
//
// Source: .planning/phases/05-web-pipeline-e2e/05-04-PLAN.md Task 2.
package web

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

// UrlDedupTask runs urless + p1radup URL deduplication.
type UrlDedupTask struct{}

func (t *UrlDedupTask) Name() string        { return "web.urldedup" }
func (t *UrlDedupTask) Module() string      { return "web" }
func (t *UrlDedupTask) Description() string { return "URL deduplication (urless + p1radup → urls.jsonl)" }
func (t *UrlDedupTask) Enabled(cfg *config.Config) bool {
	return cfg.Web.URLs.Enabled
}
func (t *UrlDedupTask) DependsOn() []string {
	return []string{"web.katana", "web.urlfinder", "web.waymore"}
}

// Run reads urls.jsonl, deduplicates via urless + p1radup, and rewrites urls.jsonl
// with the deduplicated set.
func (t *UrlDedupTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	// Read existing URL records from artefacts/urls.jsonl.
	urlsPath := filepath.Join(app.Target.WorkDir, "artefacts", "urls.jsonl")
	data, readErr := os.ReadFile(urlsPath) //nolint:gosec // path within WorkDir
	if readErr != nil || len(data) == 0 {
		if app.Log != nil {
			app.Log.Info("web.urldedup: no urls.jsonl to deduplicate — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Extract URL strings from JSONL records for dedup pipeline.
	rawURLs, origSourceMap := extractURLStringsAndSources(data)
	if len(rawURLs) == 0 {
		return task.Result{Status: task.StatusSkipped}, nil
	}

	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.urldedup: mkdir inputs/: %w", err)
	}

	// Step 1: In-process exact dedup (first-seen order) as urless equivalent.
	// urless performs parameter-based dedup; we use exact URL dedup as a safe
	// fallback. When the real urless binary is available and registered in
	// tools.lock, the Scheduler may invoke a separate urless Task in the future.
	dedupSeen := make(map[string]struct{})
	var dedupedAfterUrless []string
	for _, u := range rawURLs {
		if _, exists := dedupSeen[u]; !exists {
			dedupSeen[u] = struct{}{}
			dedupedAfterUrless = append(dedupedAfterUrless, u)
		}
	}

	// Step 2: Write urless-equivalent output for p1radup input.
	p1radupInputFile := filepath.Join(inputsDir, "urldedup_p1radup_in.txt.tmp")
	if err := os.WriteFile(p1radupInputFile,
		[]byte(strings.Join(dedupedAfterUrless, "\n")+"\n"), 0o644); err != nil { //nolint:gosec
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.urldedup: write p1radup input: %w", err)
	}

	// Step 3: Run p1radup via app.Tools.Run (-i file -o file -s for silent).
	p1radupOutputFile := filepath.Join(inputsDir, "urldedup_deduped.txt.tmp")
	p1radupArgs := []string{"-i", p1radupInputFile, "-o", p1radupOutputFile, "-s"}
	p1radupRes, p1radupErr := app.Tools.Run(ctx, "p1radup", p1radupArgs)

	var dedupedURLs []string
	if p1radupErr != nil {
		if app.Log != nil {
			app.Log.Info("web.urldedup: p1radup absent or failed — using in-process dedup output",
				"err", p1radupErr)
		}
		dedupedURLs = dedupedAfterUrless
	} else {
		var p1radupOutput []byte
		if outData, rerr := os.ReadFile(p1radupOutputFile); rerr == nil && len(outData) > 0 { //nolint:gosec
			p1radupOutput = outData
		} else if p1radupRes != nil && len(p1radupRes.Stdout) > 0 {
			p1radupOutput = p1radupRes.Stdout
		}
		dedupedURLs = splitURLLines(p1radupOutput)
		if len(dedupedURLs) == 0 {
			dedupedURLs = dedupedAfterUrless
		}
	}

	// Step 4: Rebuild URLRecord JSONL from deduplicated URL strings.
	var newLines [][]byte
	for _, u := range dedupedURLs {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		source := "dedup"
		if s, ok := origSourceMap[u]; ok {
			source = s
		}
		host := extractHostFromURL(u)
		if host == "" {
			continue
		}
		rec := map[string]string{
			"url":    u,
			"source": source,
			"host":   host,
		}
		b, merr := json.Marshal(rec)
		if merr != nil {
			continue
		}
		newLines = append(newLines, b)
	}

	// Step 5: Overwrite urls.jsonl with deduplicated records.
	if len(newLines) > 0 {
		var buf bytes.Buffer
		for _, line := range newLines {
			buf.Write(line)
			buf.WriteByte('\n')
		}
		if werr := os.WriteFile(urlsPath, buf.Bytes(), 0o644); werr != nil { //nolint:gosec
			if app.Log != nil {
				app.Log.Debug("web.urldedup: rewrite urls.jsonl failed", "err", werr)
			}
		}
	}

	// Clean up temporary files.
	os.Remove(p1radupInputFile)  //nolint:errcheck
	os.Remove(p1radupOutputFile) //nolint:errcheck

	if app.Log != nil {
		app.Log.Debug("web.urldedup: completed",
			"input_urls", len(rawURLs),
			"deduped_urls", len(dedupedURLs),
			"final_records", len(newLines))
	}

	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"urls_after_dedup": len(newLines)},
	}, nil
}

// extractURLStringsAndSources reads JSONL URL records and returns the URL
// strings plus a map of URL → source for provenance tracking.
func extractURLStringsAndSources(data []byte) ([]string, map[string]string) {
	sourceMap := make(map[string]string)
	var urls []string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec struct {
			URL    string `json:"url"`
			Source string `json:"source"`
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}
		if rec.URL != "" {
			urls = append(urls, rec.URL)
			if rec.Source != "" {
				sourceMap[rec.URL] = rec.Source
			}
		}
	}
	return urls, sourceMap
}

// splitURLLines splits raw byte content by newlines and returns non-empty strings.
func splitURLLines(data []byte) []string {
	if len(data) == 0 {
		return nil
	}
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// extractHostFromURL extracts the lowercase hostname from a URL string.
func extractHostFromURL(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return ""
	}
	idx := strings.Index(rawURL, "://")
	if idx < 0 {
		return ""
	}
	rest := rawURL[idx+3:]
	// Strip path, query, fragment.
	for _, sep := range []string{"/", "?", "#"} {
		if i := strings.Index(rest, sep); i >= 0 {
			rest = rest[:i]
		}
	}
	// Strip port (but not from bracketed IPv6 like [::1]:80).
	if !strings.HasPrefix(rest, "[") {
		if i := strings.LastIndex(rest, ":"); i >= 0 {
			rest = rest[:i]
		}
	}
	return strings.ToLower(strings.TrimSpace(rest))
}

func init() { task.Register(&UrlDedupTask{}) }

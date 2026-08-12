// urldedup.go — UrlDedupTask: URL deduplication via urless + p1radup.
//
// Name: "web.urldedup"  DependsOn: ["web.katana", "web.urlfinder", "web.waymore",
//
//	"web.subjs", "web.jsluice", "web.jsa", "web.mantra"]
//
// UrlDedupTask is the SINGLE semantic-dedup app.Tree.Append("urls") caller (WEB-14).
// It globs ALL inputs/urls.*.jsonl staging files (written by katana, urlfinder,
// waymore, subjs, jsluice, jsa, mantra), deduplicates via urless-equivalent +
// p1radup, then calls app.Tree.Append("urls") ONCE with the final deduped set.
//
// URL PIPELINE DESIGN (WEB-14, single-writer):
//
//	urls-fetch stage:   katana/urlfinder/waymore write inputs/urls.{katana,urlfinder,waymore}.jsonl
//	Pre-js-extract:     MergeStage("urls") populates artefacts/urls.jsonl from fetch-stage files
//	                    (js-extract tasks read artefacts/urls.jsonl for their JS URL input)
//	js-extract+analyze: subjs/jsluice/jsa/mantra write inputs/urls.{subjs,jsluice,jsa,mantra}.jsonl
//	urls-dedup (FINAL): this task globs ALL inputs/urls.*.jsonl (all producers), runs semantic
//	                    dedup, calls Tree.Append("urls") ONCE — replaces the intermediate file.
//
// CR-05 fix: the old direct-write to artefacts/urls.jsonl is replaced by routing
// through app.Tree.Append which:
//   - re-validates scope through the scope-enforcement boundary (T-05-09-01 mitigation)
//   - writes atomically via 4-step AtomicWriter (FOUND-04 guarantee)
//
// Axiom: LocalBackend only for both tools (D-W13).
//
// Source: .planning/phases/05-web-pipeline-e2e/05-09-PLAN.md Task 3.
package web

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

// UrlDedupTask runs urless + p1radup URL deduplication.
type UrlDedupTask struct{}

func (t *UrlDedupTask) Name() string   { return "web.urldedup" }
func (t *UrlDedupTask) Module() string { return "web" }
func (t *UrlDedupTask) Description() string {
	return "URL deduplication (urless + p1radup → urls.jsonl)"
}

func (t *UrlDedupTask) Enabled(cfg *config.Config) bool {
	return cfg.Web.URLs.Enabled
}

// DependsOn lists all URL-staging producers: fetch-stage AND js-analyze producers.
// This ensures urldedup runs AFTER all URL sources have written their staging files.
// Stage ordering that places urldedup after js-analyze is set in 05-10.
func (t *UrlDedupTask) DependsOn() []string {
	return []string{
		"web.katana", "web.urlfinder", "web.waymore",
		"web.subjs", "web.jsluice", "web.jsa", "web.mantra",
	}
}

// Run globs ALL inputs/urls.*.jsonl staging files, deduplicates via urless-equivalent
// + p1radup, and calls app.Tree.Append("urls") ONCE with the final deduped set (WEB-14).
func (t *UrlDedupTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	// Glob all URL staging files from ALL producers (fetch + js-analyze).
	pattern := filepath.Join(app.Target.WorkDir, "inputs", "urls.*.jsonl")
	matches, globErr := filepath.Glob(pattern)
	if globErr != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.urldedup: glob inputs/urls.*.jsonl: %w", globErr)
	}

	if len(matches) == 0 {
		if app.Log != nil {
			app.Log.Info("web.urldedup: no inputs/urls.*.jsonl staging files found — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Sort for deterministic processing order.
	sort.Strings(matches)

	// Collect all JSONL bytes from all staging files.
	var allData []byte
	for _, fpath := range matches {
		fileData, rerr := os.ReadFile(fpath) //nolint:gosec // path within WorkDir from trusted Glob
		if rerr != nil {
			if app.Log != nil {
				app.Log.Debug("web.urldedup: error reading staging file",
					"file", fpath, "err", rerr)
			}
			continue // non-fatal per best_effort
		}
		allData = append(allData, fileData...)
		// Ensure newline between files.
		if len(fileData) > 0 && fileData[len(fileData)-1] != '\n' {
			allData = append(allData, '\n')
		}
	}

	// Extract URL strings from JSONL records for dedup pipeline.
	rawURLs, origSourceMap := extractURLStringsAndSources(allData)
	if len(rawURLs) == 0 {
		if app.Log != nil {
			app.Log.Info("web.urldedup: no URL records in staging files — skipping")
		}
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
	// WR-03: defer cleanup immediately after creation so an early StatusErrored
	// return between here and the success path does not leak the temp file
	// across resumed/re-run invocations (mirrors arjun.go:105).
	defer os.Remove(p1radupInputFile) //nolint:errcheck
	if err := os.WriteFile(p1radupInputFile,
		[]byte(strings.Join(dedupedAfterUrless, "\n")+"\n"), 0o644); err != nil { //nolint:gosec
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.urldedup: write p1radup input: %w", err)
	}

	// Step 3: Run p1radup via app.Tools.Run (-i file -o file -s for silent).
	p1radupOutputFile := filepath.Join(inputsDir, "urldedup_deduped.txt.tmp")
	defer os.Remove(p1radupOutputFile) //nolint:errcheck // WR-03: cleanup on any return path
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
	droppedOutOfScope := 0
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
		// Drop what the Append boundary would reject. urldedup is a MULTI-SOURCE
		// aggregator (it globs every url staging file), and Append is all-or-nothing:
		// on a live run ONE junk entry — a bare ".json" fragment from a URL extractor —
		// rejected the whole batch and 1108 good URLs were never written. The output
		// Interface documents this exact division of labour: aggregators use InScope to
		// drop noise BEFORE Append, which stays strict as a guard for single-source writes.
		if !urlPassesScopeGate(app, u) {
			droppedOutOfScope++
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

	if droppedOutOfScope > 0 && app.Log != nil {
		app.Log.Info("web.urldedup: dropped out-of-scope/malformed URLs before write",
			"dropped", droppedOutOfScope, "kept", len(newLines))
	}

	// Step 5: Route deduplicated records through app.Tree.Append("urls") — the scope-
	// enforcement boundary (T-05-09-01 mitigation: replaces the prior direct-write bypass).
	// This is the SINGLE semantic-dedup Append writer for urls (WEB-14).
	//
	// WR-02: urldedup is the SOLE authoritative writer of artefacts/urls.jsonl — it
	// has no fallback writer. A swallowed Append failure (scope rejection, atomic-write
	// failure, disk full) would leave the final URL artefact empty/stale while the task
	// reports success with a nonzero urls_after_dedup. Propagate as StatusErrored so the
	// failure is observable; best_effort (D-W12) is applied by the caller (stage loop
	// logs and continues), not by hiding the error here.
	if len(newLines) > 0 {
		if appendErr := app.Tree.Append("urls", newLines); appendErr != nil {
			if app.Log != nil {
				app.Log.Warn("web.urldedup: Tree.Append(urls) failed — final urls.jsonl not written",
					"records", len(newLines), "err", appendErr)
			}
			return task.Result{Status: task.StatusErrored},
				fmt.Errorf("web.urldedup: Tree.Append(urls): %w", appendErr)
		}
	}

	// Temp files are removed by the deferred os.Remove calls registered at creation (WR-03).

	if app.Log != nil {
		app.Log.Debug("web.urldedup: completed",
			"staging_files", len(matches),
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
//
// WR-05: accepts BOTH schemed URLs ("https://example.com/path") and scheme-less
// authorities ("example.com/path 200"). Plain-text tool findings from
// nomore403/Gxss/arjun are not guaranteed to be schemed; the prior "://"-only
// implementation dropped their host, weakening the SARIF FindingRecord.Host.
// The first whitespace-delimited token is taken, an optional scheme is stripped,
// then path/query/fragment and port are removed (bracketed IPv6 ports preserved).
func extractHostFromURL(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return ""
	}
	// Tool output lines may be "<url-or-host> <status> ..."; the host/URL is the
	// first whitespace-delimited token.
	if i := strings.IndexAny(rawURL, " \t"); i >= 0 {
		rawURL = rawURL[:i]
	}
	// Strip an optional scheme ("https://example.com" -> "example.com"); leave
	// scheme-less authorities untouched.
	if idx := strings.Index(rawURL, "://"); idx >= 0 {
		rawURL = rawURL[idx+3:]
	}
	rest := rawURL
	// Strip userinfo ("user:pass@host" -> "host") so credentials never leak into host.
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		rest = rest[at+1:]
	}
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

// urlPassesScopeGate reports whether rawURL will survive OutputTree.Append's scope
// check, mirroring DefaultScopeFilter.IsInScopeURL exactly: parseable, no userinfo
// (SUBD-05 credential-leak guard), a real hostname, and that host in workspace scope.
//
// Mirroring matters — a filter LOOSER than the boundary still lets the batch be
// rejected, which is the failure this exists to prevent.
func urlPassesScopeGate(app *appctx.AppContext, rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil || u.User != nil {
		return false
	}
	host := u.Hostname()
	if host == "" {
		return false
	}
	if app == nil || app.Tree == nil {
		return true // no scope configured — the boundary will not reject either
	}
	return app.Tree.InScope(host)
}

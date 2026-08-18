package report_test

import (
	"bytes"
	"context"
	"encoding/csv"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/ingest"
	"github.com/six2dez/reconftw/internal/core/log"
	"github.com/six2dez/reconftw/internal/core/report"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// seedStore populates <workDir>/store.db with one completed scan (+ a finding
// and a host) attached to target, using the real ingest path — the same store
// the production report renderer reads. Returns the target it seeded.
func seedStore(t *testing.T, workDir, target string) {
	t.Helper()
	ctx := context.Background()

	artefacts := filepath.Join(workDir, "artefacts")
	if err := os.MkdirAll(artefacts, 0o755); err != nil {
		t.Fatalf("mkdir artefacts: %v", err)
	}
	writeLines := func(name string, lines ...string) {
		body := strings.Join(lines, "\n") + "\n"
		if err := os.WriteFile(filepath.Join(artefacts, name), []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	writeLines("hosts.jsonl", `{"host":"api.example.com","ip":"1.2.3.4"}`)
	writeLines("findings.jsonl",
		`{"type":"http","host":"api.example.com","template_id":"exposed-panel","severity":"high","matched_at":"https://api.example.com/admin"}`,
	)

	// dataDir == workDir so store.db lands at <workDir>/store.db (where the
	// renderer reads it); artefacts are read from <workDir>/artefacts.
	if _, err := ingest.ScanIntoStore(ctx, workDir, workDir, target, "all", quietLogger()); err != nil {
		t.Fatalf("seed ScanIntoStore: %v", err)
	}
}

// TestRenderAll_OllamaWritesAIReport is the production-path proof for INTEG-06:
// with AI.Enabled=true and Provider="ollama" pointed at an httptest server,
// RenderAll (reached by `reconftw report`) writes reports/ai-report.md
// containing the local server's response. This is the gap the direct-Generate
// unit test cannot catch — before the Step-10 gate was opened, the keyless
// ollama default never ran through RenderAll.
func TestRenderAll_OllamaWritesAIReport(t *testing.T) {
	const wantResp = "RENDERALL_OLLAMA_SUMMARY_99"
	ctx := context.Background()
	target := "example.com"
	workDir := t.TempDir()
	seedStore(t, workDir, target)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/generate" {
			t.Errorf("ollama request path = %q; want /api/generate", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"response":"`+wantResp+`"}`)
	}))
	defer srv.Close()

	cfg := config.Defaults()
	cfg.AI.Enabled = true
	cfg.AI.Provider = "ollama"
	cfg.AI.OllamaHost = srv.URL

	renderer, err := report.NewReportRenderer(workDir, cfg, quietLogger(), &log.Redactor{})
	if err != nil {
		t.Fatalf("NewReportRenderer: %v", err)
	}
	defer renderer.Close() //nolint:errcheck

	res, err := renderer.RenderAll(ctx, target, "", false, false)
	if err != nil {
		t.Fatalf("RenderAll: %v", err)
	}

	aiPath := filepath.Join(res.Dir, "ai-report.md")
	data, err := os.ReadFile(aiPath)
	if err != nil {
		t.Fatalf("ai-report.md not written (production ollama gate did not fire): %v", err)
	}
	if !strings.Contains(string(data), wantResp) {
		t.Errorf("ai-report.md = %q; want it to contain %q", string(data), wantResp)
	}
}

// TestRenderAll_AnthropicEmptyKeyWritesNothing verifies the renderer gate is
// closed for a cloud provider with no key: no ai-report.md, no cloud egress.
func TestRenderAll_AnthropicEmptyKeyWritesNothing(t *testing.T) {
	ctx := context.Background()
	target := "example.com"
	workDir := t.TempDir()
	seedStore(t, workDir, target)

	cfg := config.Defaults()
	cfg.AI.Enabled = true
	cfg.AI.Provider = "anthropic"
	cfg.AI.AnthropicKey = "" // empty cloud key — gate must stay closed

	renderer, err := report.NewReportRenderer(workDir, cfg, quietLogger(), &log.Redactor{})
	if err != nil {
		t.Fatalf("NewReportRenderer: %v", err)
	}
	defer renderer.Close() //nolint:errcheck

	res, err := renderer.RenderAll(ctx, target, "", false, false)
	if err != nil {
		t.Fatalf("RenderAll: %v", err)
	}

	aiPath := filepath.Join(res.Dir, "ai-report.md")
	if _, err := os.Stat(aiPath); !os.IsNotExist(err) {
		t.Errorf("ai-report.md exists for anthropic+empty-key; want no file (gate should be closed), stat err=%v", err)
	}
}

// TestRenderAll_AIDisabledWritesNothing verifies AI reporting stays opt-in: with
// AI.Enabled=false, no ai-report.md is written even for the ollama default.
func TestRenderAll_AIDisabledWritesNothing(t *testing.T) {
	ctx := context.Background()
	target := "example.com"
	workDir := t.TempDir()
	seedStore(t, workDir, target)

	cfg := config.Defaults() // AI.Enabled defaults to false, Provider defaults to ollama

	renderer, err := report.NewReportRenderer(workDir, cfg, quietLogger(), &log.Redactor{})
	if err != nil {
		t.Fatalf("NewReportRenderer: %v", err)
	}
	defer renderer.Close() //nolint:errcheck

	res, err := renderer.RenderAll(ctx, target, "", false, false)
	if err != nil {
		t.Fatalf("RenderAll: %v", err)
	}

	aiPath := filepath.Join(res.Dir, "ai-report.md")
	if _, err := os.Stat(aiPath); !os.IsNotExist(err) {
		t.Errorf("ai-report.md exists with AI.Enabled=false; want no file, stat err=%v", err)
	}
}

// --- Plan 15-11 Task 1: per-scan asset scoping (acceptance gate 9) ---------
//
// Gate 9: "a report contains exclusively the requested scan's observations".
//
// Every assertion below is made against the RENDERED FILE CONTENT (the CSV the
// renderer wrote, parsed with encoding/csv), never against an intermediate
// slice or a store query — the defect these tests pin lived between the query
// and the file.

// writeArtefacts writes <workDir>/artefacts/<name> for each entry. A value of
// "" produces a ZERO-BYTE file, which is what an empty publish leaves on disk
// (see web.publishEmptyStage) and is a different state from an absent file.
func writeArtefacts(t *testing.T, workDir string, files map[string]string) {
	t.Helper()
	artefacts := filepath.Join(workDir, "artefacts")
	if err := os.MkdirAll(artefacts, 0o755); err != nil {
		t.Fatalf("mkdir artefacts: %v", err)
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(artefacts, name), []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
}

// ingestRun ingests the current artefact set as one scan and returns its Result.
func ingestRun(t *testing.T, dataDir, workDir, target string) ingest.Result {
	t.Helper()
	res, err := ingest.ScanIntoStore(context.Background(), dataDir, workDir, target, "recon", quietLogger())
	if err != nil {
		t.Fatalf("ScanIntoStore: %v", err)
	}
	return res
}

// csvRows parses a rendered CSV and returns its DATA rows (header stripped).
func csvRows(t *testing.T, path string) [][]string {
	t.Helper()
	f, err := os.Open(path) //nolint:gosec // test-controlled path
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close() //nolint:errcheck
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if len(rows) == 0 {
		t.Fatalf("%s has no header row — the renderer wrote nothing parseable", path)
	}
	return rows[1:]
}

// hostLine / urlLine / findingLine build artefact records in the shapes the real
// producers emit: hosts.jsonl's {"host","ip"}, internal/extract/urls.URLRecord
// and web.FindingRecord.
func hostLine(host, ip string) string {
	return `{"host":"` + host + `","ip":"` + ip + `"}`
}

func urlLine(u, host string) string {
	return `{"url":"` + u + `","host":"` + host + `"}`
}

func findingLine(host, templateID, matchedAt string) string {
	return `{"type":"http","host":"` + host + `","template_id":"` + templateID +
		`","severity":"high","matched_at":"` + matchedAt + `"}`
}

// seedGate9Store builds the gate-9 fixture: target T has 5 URLs in total; scan A
// observed all 5 URLs plus 2 hosts; scan B observed the SAME 2 hosts and ZERO
// URLs. Returns (dataDir, scanA, scanB).
func seedGate9Store(t *testing.T, target string) (string, string, string) {
	t.Helper()
	dataDir := t.TempDir()
	workDir := filepath.Join(dataDir, "ws")

	hosts := hostLine("api."+target, "1.1.1.1") + "\n" + hostLine("www."+target, "2.2.2.2") + "\n"
	var urls strings.Builder
	for i := 1; i <= 5; i++ {
		urls.WriteString(urlLine("https://api."+target+"/p"+strconv.Itoa(i), "api."+target) + "\n")
	}
	writeArtefacts(t, workDir, map[string]string{
		"hosts.jsonl": hosts,
		"urls.jsonl":  urls.String(),
	})
	scanA := ingestRun(t, dataDir, workDir, target)

	// Scan B: the same hosts, and an EMPTY urls artefact — the on-disk state an
	// empty publish produces. The 5 URLs stay in the store, attached to T.
	writeArtefacts(t, workDir, map[string]string{
		"hosts.jsonl": hosts,
		"urls.jsonl":  "",
	})
	scanB := ingestRun(t, dataDir, workDir, target)

	if scanA.ScanID == scanB.ScanID {
		t.Fatalf("both runs share scan id %s — the fixture cannot distinguish them", scanA.ScanID)
	}
	if scanA.URLs != 5 {
		t.Fatalf("scan A ingested %d URLs; want 5 (the fixture is wrong, not the renderer)", scanA.URLs)
	}
	if scanB.URLs != 0 {
		t.Fatalf("scan B ingested %d URLs; want 0", scanB.URLs)
	}
	return dataDir, scanA.ScanID, scanB.ScanID
}

// renderScan renders one scan and returns the directory holding its output.
func renderScan(t *testing.T, dataDir, target, scanID string, includeHistorical bool) string {
	t.Helper()
	return renderScanWithLog(t, dataDir, target, scanID, includeHistorical, quietLogger())
}

func renderScanWithLog(t *testing.T, dataDir, target, scanID string, includeHistorical bool, logger *slog.Logger) string {
	t.Helper()
	r, err := report.NewReportRenderer(dataDir, config.Defaults(), logger, &log.Redactor{})
	if err != nil {
		t.Fatalf("NewReportRenderer: %v", err)
	}
	defer r.Close() //nolint:errcheck
	res, err := r.RenderAll(context.Background(), target, scanID, false, includeHistorical)
	if err != nil {
		t.Fatalf("RenderAll: %v", err)
	}
	return res.Dir
}

// TestRenderAll_Gate9_ScanWithZeroURLsRendersZeroURLs is acceptance gate 9.
//
// Before this change the fetch-then-filter path kept any asset kind with no
// observations at all, so scan B — which observed 2 hosts and no URLs —
// rendered every URL target T had ever had.
func TestRenderAll_Gate9_ScanWithZeroURLsRendersZeroURLs(t *testing.T) {
	const target = "gate9.example"
	dataDir, _, scanB := seedGate9Store(t, target)

	dir := renderScan(t, dataDir, target, scanB, false)

	urlRows := csvRows(t, filepath.Join(dir, "urls.csv"))
	if len(urlRows) != 0 {
		t.Errorf("scan B rendered %d URLs; want 0 — the report is showing the target's "+
			"history, not the scan's observations: %v", len(urlRows), urlRows)
	}
	hostRows := csvRows(t, filepath.Join(dir, "hosts.csv"))
	if len(hostRows) != 2 {
		t.Errorf("scan B rendered %d hosts; want the 2 it observed: %v", len(hostRows), hostRows)
	}
	body, err := os.ReadFile(filepath.Join(dir, "report.html"))
	if err != nil {
		t.Fatalf("read report.html: %v", err)
	}
	if strings.Contains(string(body), "/p1") {
		t.Error("report.html contains a URL scan B never observed")
	}
}

// TestRenderAll_Gate9_ScanAStillRendersItsURLs is the control: the scoping must
// scope, not empty. Without it a renderer that emitted nothing would pass the
// gate-9 assertion above.
func TestRenderAll_Gate9_ScanAStillRendersItsURLs(t *testing.T) {
	const target = "gate9ctl.example"
	dataDir, scanA, _ := seedGate9Store(t, target)

	dir := renderScan(t, dataDir, target, scanA, false)

	urlRows := csvRows(t, filepath.Join(dir, "urls.csv"))
	if len(urlRows) != 5 {
		t.Errorf("scan A rendered %d URLs; want the 5 it observed: %v", len(urlRows), urlRows)
	}
}

// TestRenderAll_IncludeHistoricalRendersHistoryWithMarker proves the widening is
// available AND that it announces itself in the rendered output.
func TestRenderAll_IncludeHistoricalRendersHistoryWithMarker(t *testing.T) {
	const target = "hist.example"
	dataDir, _, scanB := seedGate9Store(t, target)

	dir := renderScan(t, dataDir, target, scanB, true)

	urlRows := csvRows(t, filepath.Join(dir, "urls.csv"))
	if len(urlRows) != 5 {
		t.Errorf("includeHistorical rendered %d URLs; want the target's full 5: %v", len(urlRows), urlRows)
	}
	body, err := os.ReadFile(filepath.Join(dir, "report.html"))
	if err != nil {
		t.Fatalf("read report.html: %v", err)
	}
	if !strings.Contains(string(body), report.HistoricalNotice) {
		t.Errorf("report.html does not carry the historical marker %q — a report that "+
			"silently widened its scope is unattributable afterwards", report.HistoricalNotice)
	}
}

// TestRenderAll_PaginationCoversEveryRowExactlyOnce drives three pages with a
// test-lowered page size: no duplicates from an off-by-one offset, no gaps.
func TestRenderAll_PaginationCoversEveryRowExactlyOnce(t *testing.T) {
	const target = "paging.example"
	const wantFindings = 7 // 3 pages at page size 3: 3 + 3 + 1
	dataDir := t.TempDir()
	workDir := filepath.Join(dataDir, "ws")

	var findings strings.Builder
	for i := 1; i <= wantFindings; i++ {
		n := strconv.Itoa(i)
		findings.WriteString(findingLine("api."+target, "tpl-"+n, "https://api."+target+"/f"+n) + "\n")
	}
	writeArtefacts(t, workDir, map[string]string{
		"hosts.jsonl":    hostLine("api."+target, "1.1.1.1") + "\n",
		"findings.jsonl": findings.String(),
	})
	res := ingestRun(t, dataDir, workDir, target)
	if res.Findings != wantFindings {
		t.Fatalf("fixture ingested %d findings; want %d", res.Findings, wantFindings)
	}

	r, err := report.NewReportRenderer(dataDir, config.Defaults(), quietLogger(), &log.Redactor{})
	if err != nil {
		t.Fatalf("NewReportRenderer: %v", err)
	}
	defer r.Close() //nolint:errcheck
	r.SetPageSize(3)
	rendered, err := r.RenderAll(context.Background(), target, res.ScanID, false, false)
	if err != nil {
		t.Fatalf("RenderAll: %v", err)
	}

	rows := csvRows(t, filepath.Join(rendered.Dir, "findings.csv"))
	if len(rows) != wantFindings {
		t.Fatalf("rendered %d findings across 3 pages; want %d", len(rows), wantFindings)
	}
	seen := map[string]int{}
	for _, row := range rows {
		seen[row[0]]++ // column 0 is the finding id
	}
	if len(seen) != wantFindings {
		t.Errorf("rendered %d DISTINCT finding ids; want %d — paging duplicated or dropped rows",
			len(seen), wantFindings)
	}
	for id, n := range seen {
		if n != 1 {
			t.Errorf("finding id %s appears %d times; want exactly once", id, n)
		}
	}
}

// TestRenderAll_ScanWithNoObservationsRendersEmptyReport pins the replacement
// for the deleted fallback: nothing observed renders nothing, loudly.
func TestRenderAll_ScanWithNoObservationsRendersEmptyReport(t *testing.T) {
	const target = "empty.example"
	dataDir := t.TempDir()
	workDir := filepath.Join(dataDir, "ws")

	// Run 1 populates the target's history.
	writeArtefacts(t, workDir, map[string]string{
		"hosts.jsonl":    hostLine("api."+target, "1.1.1.1") + "\n",
		"urls.jsonl":     urlLine("https://api."+target+"/a", "api."+target) + "\n",
		"findings.jsonl": findingLine("api."+target, "panel", "https://api."+target+"/a") + "\n",
	})
	_ = ingestRun(t, dataDir, workDir, target)

	// Run 2 observes nothing at all — every artefact is zero bytes.
	writeArtefacts(t, workDir, map[string]string{
		"hosts.jsonl":    "",
		"urls.jsonl":     "",
		"findings.jsonl": "",
	})
	empty := ingestRun(t, dataDir, workDir, target)

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	dir := renderScanWithLog(t, dataDir, target, empty.ScanID, false, logger)

	for _, name := range []string{"findings.csv", "hosts.csv", "urls.csv"} {
		if rows := csvRows(t, filepath.Join(dir, name)); len(rows) != 0 {
			t.Errorf("%s has %d rows for a scan that observed nothing; want 0: %v", name, len(rows), rows)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "report.html")); err != nil {
		t.Errorf("an empty report must still be a report: %v", err)
	}
	if !strings.Contains(logBuf.String(), "rendering an EMPTY report") {
		t.Errorf("no warning logged for the empty render; log was: %s", logBuf.String())
	}
}

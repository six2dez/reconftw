package report

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	// modernc.org/sqlite registers the "sqlite" driver name (XCUT-02 pure-Go).
	_ "modernc.org/sqlite"

	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/log"
	"github.com/six2dez/reconftw/internal/core/output"
	sqlcgen "github.com/six2dez/reconftw/internal/store/sqlc"
)

// ReportRenderer reads from store.db for a given scan and writes all report
// formats to the workspace reports/ directory. No scan execution occurs (D-03).
//
// Security: store.db is opened READ-ONLY (T-10-03-05 mitigation — ?mode=ro).
type ReportRenderer struct {
	db       *sql.DB
	q        *sqlcgen.Queries
	workDir  string
	cfg      *config.Config
	log      *slog.Logger
	redactor *log.Redactor
}

// NewReportRenderer opens store.db at workDir/store.db in read-only mode and
// returns a ReportRenderer. Returns an error if the database cannot be opened.
func NewReportRenderer(workDir string, cfg *config.Config, logger *slog.Logger, rdct *log.Redactor) (*ReportRenderer, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if rdct == nil {
		rdct = &log.Redactor{}
	}
	dbPath := filepath.Join(workDir, "store.db")
	// ?mode=ro: read-only — any write attempt returns SQLITE_READONLY (T-10-03-05).
	db, err := sql.Open("sqlite", dbPath+"?mode=ro")
	if err != nil {
		return nil, fmt.Errorf("report: open store: %w", err)
	}
	return &ReportRenderer{
		db:       db,
		q:        sqlcgen.New(db),
		workDir:  workDir,
		cfg:      cfg,
		log:      logger,
		redactor: rdct,
	}, nil
}

// Close releases the database connection.
func (r *ReportRenderer) Close() error {
	return r.db.Close()
}

// RenderAll resolves the scan, fetches findings/hosts/URLs and writes all
// report formats to workDir/reports/.
//
// Scan resolution order:
//  1. If scanID is non-empty, use GetScan(scanID).
//  2. Otherwise use GetLatestCompletedScanForTarget(targetID).
//
// If --allow-partial is set in the future, the caller should pass
// allowPartial=true to accept incomplete scans; currently the method
// requires a completed scan unless scanID is explicitly specified.
func (r *ReportRenderer) RenderAll(ctx context.Context, targetID, scanID string) error {
	// Step 1: resolve scan.
	var scan sqlcgen.Scan
	var err error
	if scanID != "" {
		scan, err = r.q.GetScan(ctx, scanID)
	} else {
		scan, err = r.q.GetLatestCompletedScanForTarget(ctx, targetID)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("report: no completed scan found for target %q (use --scan-id to specify an explicit scan)", targetID)
	}
	if err != nil {
		return fmt.Errorf("report: get scan: %w", err)
	}

	r.log.InfoContext(ctx, "report: rendering scan", "scan_id", scan.ID, "target", scan.TargetID)

	// Step 2: fetch findings (up to 10000 for reports — no cursor pagination needed).
	rawFindings, err := r.q.ListFindingsForTarget(ctx, sqlcgen.ListFindingsForTargetParams{
		TargetID: targetID,
		Limit:    10000,
		Offset:   0,
	})
	if err != nil {
		return fmt.Errorf("report: list findings: %w", err)
	}
	findings := make([]*sqlcgen.Finding, len(rawFindings))
	for i := range rawFindings {
		findings[i] = &rawFindings[i]
	}

	// Fetch hosts.
	rawHosts, err := r.q.ListHostsCursor(ctx, sqlcgen.ListHostsCursorParams{
		TargetID:     targetID,
		CdnFilter:    "",
		CursorSeenAt: 0,
		CursorLastID: 0,
		RowLimit:     10000,
	})
	if err != nil {
		return fmt.Errorf("report: list hosts: %w", err)
	}
	hosts := make([]*sqlcgen.Host, len(rawHosts))
	for i := range rawHosts {
		hosts[i] = &rawHosts[i]
	}

	// Fetch URLs.
	rawURLs, err := r.q.ListURLsCursor(ctx, sqlcgen.ListURLsCursorParams{
		HostIDFilter:      0,
		StatusCodeFilter:  0,
		ContentTypeFilter: "",
		CursorSeenAt:      0,
		CursorLastID:      0,
		RowLimit:          10000,
	})
	if err != nil {
		return fmt.Errorf("report: list urls: %w", err)
	}
	urls := make([]*sqlcgen.URL, len(rawURLs))
	for i := range rawURLs {
		urls[i] = &rawURLs[i]
	}

	// Step 3: ensure reports directory exists.
	reportsDir := filepath.Join(r.workDir, "reports")
	if err := os.MkdirAll(reportsDir, 0o755); err != nil {
		return fmt.Errorf("report: mkdir reports: %w", err)
	}

	// Build hotlist first (used in HTML).
	topN := 10
	if r.cfg != nil && r.cfg.Output.HotlistTop > 0 {
		topN = r.cfg.Output.HotlistTop
	}
	hotlistItems := BuildHotlist(findings, nil, topN)

	// Step 4: render HTML report.
	startedAtStr := formatUnixTS(scan.StartedAt)
	finishedAtStr := "running"
	if scan.FinishedAt != nil {
		finishedAtStr = time.Unix(*scan.FinishedAt, 0).UTC().Format(time.RFC3339)
	}
	version := ""
	if scan.ReconftwVersion != nil {
		version = *scan.ReconftwVersion
	}
	toolVersions := ""
	if scan.ToolVersionsJson != nil {
		toolVersions = *scan.ToolVersionsJson
	}

	htmlData := ReportData{
		Target:          scan.TargetID,
		ScanID:          scan.ID,
		StartedAt:       startedAtStr,
		FinishedAt:      finishedAtStr,
		ReconftwVersion: version,
		FindingsCount:   int(scan.FindingsCount),
		SubdomainCount:  int(scan.SubdomainCount),
		URLCount:        int(scan.UrlCount),
		HotlistTop:      topN,
		HotlistItems:    hotlistItems,
		Findings:        FindingsToRows(findings),
		Hosts:           HostsToRows(hosts),
		URLs:            URLsToRows(urls),
		ConfigSnapshot:  scan.ConfigOverridesJson,
		ToolVersions:    toolVersions,
	}

	htmlPath := filepath.Join(reportsDir, "report.html")
	if err := RenderHTML(htmlData, htmlPath); err != nil {
		return fmt.Errorf("report: html: %w", err)
	}
	r.log.InfoContext(ctx, "report: wrote HTML report", "path", htmlPath)

	// Step 5: write CSV files.
	if err := WriteAllCSV(reportsDir, findings, hosts, urls); err != nil {
		return fmt.Errorf("report: csv: %w", err)
	}

	// Step 6: write SARIF.
	sarifPath := filepath.Join(reportsDir, "findings.sarif")
	if err := WriteSARIF(sarifPath, version, findings); err != nil {
		return fmt.Errorf("report: sarif: %w", err)
	}

	// Step 7: write hotlist JSON.
	hotlistPath := filepath.Join(reportsDir, "hotlist.json")
	if err := WriteHotlist(hotlistPath, hotlistItems); err != nil {
		return fmt.Errorf("report: hotlist: %w", err)
	}

	// Step 8: write Faraday export (gated on Integrations.Faraday.Enabled).
	if r.cfg != nil && r.cfg.Integrations.Faraday.Enabled {
		faradayPath := filepath.Join(reportsDir, "faraday.json")
		if err := WriteFaraday(faradayPath, findings, hosts); err != nil {
			r.log.WarnContext(ctx, "report: faraday export failed (non-fatal)", "err", err)
		} else {
			r.log.InfoContext(ctx, "report: wrote Faraday export", "path", faradayPath)
		}
	}

	// Step 9: write notes.jsonl (canonical REPORT-01 artefact — always written).
	if err := WriteNotesJSONL(reportsDir); err != nil {
		return fmt.Errorf("report: notes.jsonl: %w", err)
	}

	// Step 10: AI report (best-effort — errors are logged but do not abort).
	//
	// INTEG-06: provider-ready gate. This MIRRORS the in-Generate cloud-egress
	// guard (defense-in-depth): the local ollama provider runs WITHOUT a key
	// (so the coherent local-first default actually executes through the
	// production `reconftw report` path), while a cloud provider only runs when
	// its key is present — an empty cloud key opens no gate and makes no call.
	// An empty provider is treated as the historical anthropic cloud default.
	if r.cfg != nil && r.cfg.AI.Enabled {
		provider := strings.ToLower(r.cfg.AI.Provider)
		ready := provider == "ollama" ||
			(provider == "openai" && string(r.cfg.AI.OpenAIKey) != "") ||
			((provider == "anthropic" || provider == "") && string(r.cfg.AI.AnthropicKey) != "")
		if ready {
			reporter := NewAIReporter(&r.cfg.AI, r.redactor, r.log)
			aiText, aiErr := reporter.Generate(ctx, &scan, findings)
			if aiErr != nil {
				r.log.WarnContext(ctx, "report: AI report failed (non-fatal)", "err", aiErr)
			} else {
				aiPath := filepath.Join(reportsDir, "ai-report.md")
				if wErr := output.WriteFile(aiPath, []byte(aiText), 0o644); wErr != nil {
					r.log.WarnContext(ctx, "report: write AI report failed (non-fatal)", "err", wErr)
				} else {
					r.log.InfoContext(ctx, "report: wrote AI report", "path", aiPath)
				}
			}
		}
	}

	return nil
}

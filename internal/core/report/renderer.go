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
// reportRowLimit caps how many rows of each kind a report renders. Reaching it
// used to truncate in silence, so a report over a large target looked complete
// while omitting findings — the one thing a report must never do quietly.
// warnIfTruncated turns that into an explicit warning.
const reportRowLimit = 10000

// warnIfTruncated logs when a result set came back exactly at the cap, which
// means there were probably more rows than the report shows.
func (r *ReportRenderer) warnIfTruncated(ctx context.Context, kind string, got int) {
	if got >= reportRowLimit {
		r.log.WarnContext(ctx, "report: result set hit the row cap — the report is TRUNCATED",
			"kind", kind, "cap", reportRowLimit)
	}
}

// RenderAll renders the latest completed scan for targetID, or the explicit
// scanID when given. allowPartial additionally accepts the most recent
// INCOMPLETE scan when no completed one exists — the behaviour --allow-partial
// always advertised while being read by nothing.
// narrowToScan filters target-wide asset lists down to the rows this scan
// recorded in scan_observation.
//
// Fallback: a scan with NO observations keeps the target-wide lists. Rows
// predating the observation writer, or a run whose ingest failed partway,
// would otherwise render as an empty report — silently losing data is worse
// than the over-broad report this replaces. The fallback is logged so the
// difference is visible rather than assumed.
func (r *ReportRenderer) narrowToScan(
	ctx context.Context,
	scanID string,
	findings []*sqlcgen.Finding,
	hosts []*sqlcgen.Host,
	urls []*sqlcgen.URL,
) ([]*sqlcgen.Finding, []*sqlcgen.Host, []*sqlcgen.URL) {
	obs, err := r.q.ListObservationsForScan(ctx, scanID)
	if err != nil {
		r.log.WarnContext(ctx, "report: could not read scan observations — "+
			"falling back to target-wide asset lists", "scan_id", scanID, "err", err)
		return findings, hosts, urls
	}
	if len(obs) == 0 {
		r.log.WarnContext(ctx, "report: scan recorded no observations — rendering "+
			"target-wide asset lists, which may include assets this scan did not see",
			"scan_id", scanID)
		return findings, hosts, urls
	}

	seen := map[string]map[int64]struct{}{}
	for _, o := range obs {
		if seen[o.AssetKind] == nil {
			seen[o.AssetKind] = map[int64]struct{}{}
		}
		seen[o.AssetKind][o.AssetID] = struct{}{}
	}
	// A kind with no observations at all is left unfiltered: it means this scan
	// mode does not produce that asset kind (a subs-only run records no URLs),
	// not that the scan observed none of them.
	keep := func(kind string, id int64) bool {
		ids, ok := seen[kind]
		if !ok {
			return true
		}
		_, found := ids[id]
		return found
	}

	outF := findings[:0:0]
	for _, f := range findings {
		if keep("finding", f.ID) {
			outF = append(outF, f)
		}
	}
	outH := hosts[:0:0]
	for _, h := range hosts {
		if keep("host", h.ID) {
			outH = append(outH, h)
		}
	}
	outU := urls[:0:0]
	for _, u := range urls {
		if keep("url", u.ID) {
			outU = append(outU, u)
		}
	}
	r.log.InfoContext(ctx, "report: narrowed to this scan's observations",
		"scan_id", scanID,
		"findings", len(outF), "hosts", len(outH), "urls", len(outU))
	return outF, outH, outU
}

func (r *ReportRenderer) RenderAll(ctx context.Context, targetID, scanID string, allowPartial bool) error {
	// Step 1: resolve scan.
	var scan sqlcgen.Scan
	var err error
	switch {
	case scanID != "":
		scan, err = r.q.GetScan(ctx, scanID)
	default:
		scan, err = r.q.GetLatestCompletedScanForTarget(ctx, targetID)
		if errors.Is(err, sql.ErrNoRows) && allowPartial {
			// Fall back to the most recent scan of any status. Reports built
			// this way describe a run that never finished, so say so loudly
			// rather than presenting partial data as a finished assessment.
			scans, lerr := r.q.ListScansForTarget(ctx, sqlcgen.ListScansForTargetParams{
				TargetID: targetID, Limit: 1, Offset: 0,
			})
			if lerr == nil && len(scans) > 0 {
				scan, err = scans[0], nil
				r.log.WarnContext(ctx, "report: no completed scan — rendering an INCOMPLETE scan (--allow-partial)",
					"scan_id", scan.ID, "status", scan.Status)
			}
		}
	}
	if errors.Is(err, sql.ErrNoRows) {
		hint := "use --scan-id to specify an explicit scan"
		if !allowPartial {
			hint += ", or --allow-partial to accept an unfinished one"
		}
		return fmt.Errorf("report: no completed scan found for target %q (%s)", targetID, hint)
	}
	if err != nil {
		return fmt.Errorf("report: get scan: %w", err)
	}

	// An explicit --scan-id bypassed the completed-scan requirement entirely, so
	// `report --scan-id <running scan>` rendered a half-finished run as a
	// finished assessment while --allow-partial — the flag whose entire purpose
	// is to opt into that — sat unread. Apply the same rule to both paths.
	if !allowPartial && scan.Status != "completed" {
		return fmt.Errorf(
			"report: scan %s is %q, not completed — pass --allow-partial to render it anyway",
			scan.ID, scan.Status)
	}

	// The resolved scan is the authority on which target this report describes.
	// An explicit --scan-id was never checked against the target argument, so
	// `report --target A --scan-id <a scan of B>` rendered B's scan header over
	// A's findings, hosts and URLs — a report that looks authoritative and
	// describes an asset the scan never touched. Refuse rather than guess.
	if targetID != "" && scan.TargetID != targetID {
		return fmt.Errorf(
			"report: scan %s belongs to target %q, not %q — refusing to render a "+
				"report mixing one scan's header with another target's data",
			scan.ID, scan.TargetID, targetID)
	}
	// With no --target the scan supplies it, so every query below is scoped to
	// the scan's own target rather than to whatever the caller passed.
	targetID = scan.TargetID

	r.log.InfoContext(ctx, "report: rendering scan", "scan_id", scan.ID, "target", scan.TargetID)

	// Step 2: fetch findings (up to 10000 for reports — no cursor pagination needed).
	rawFindings, err := r.q.ListFindingsForTarget(ctx, sqlcgen.ListFindingsForTargetParams{
		TargetID: targetID,
		Limit:    reportRowLimit,
		Offset:   0,
	})
	if err != nil {
		return fmt.Errorf("report: list findings: %w", err)
	}
	r.warnIfTruncated(ctx, "findings", len(rawFindings))
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
		RowLimit:     reportRowLimit,
	})
	if err != nil {
		return fmt.Errorf("report: list hosts: %w", err)
	}
	r.warnIfTruncated(ctx, "hosts", len(rawHosts))
	hosts := make([]*sqlcgen.Host, len(rawHosts))
	for i := range rawHosts {
		hosts[i] = &rawHosts[i]
	}

	// Fetch URLs for THIS target.
	//
	// This used to call ListURLsCursor with HostIDFilter 0, which disables the
	// filter — so the URL section listed every URL in the shared store,
	// including other targets' and other engagements'. On a store holding
	// several targets the report leaked them into each other, and the 10000-row
	// cap meant the actual target's URLs could be crowded out entirely.
	rawURLs, err := r.q.ListURLsForTarget(ctx, sqlcgen.ListURLsForTargetParams{
		TargetID: targetID,
		Limit:    reportRowLimit,
		Offset:   0,
	})
	if err != nil {
		return fmt.Errorf("report: list urls: %w", err)
	}
	r.warnIfTruncated(ctx, "urls", len(rawURLs))
	urls := make([]*sqlcgen.URL, len(rawURLs))
	for i := range rawURLs {
		urls[i] = &rawURLs[i]
	}

	// Narrow the target-wide lists to what THIS scan actually observed.
	//
	// Everything above is target-scoped, which is right for a single-scan store
	// but wrong the moment a target has been scanned twice: a report for scan 2
	// listed assets that only scan 1 ever saw, so it described a state that
	// never existed and could not represent an asset disappearing. The
	// scan_observation rows recorded during ingest are the per-scan record; use
	// them.
	findings, hosts, urls = r.narrowToScan(ctx, scan.ID, findings, hosts, urls)

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

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
	// pageSize overrides the query page size; 0 means reportRowLimit.
	pageSize int64
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

// reportRowLimit is the PAGE SIZE for every report query, not a truncation
// point. It used to be a hard cap: one query per asset kind with LIMIT 10000
// and no follow-up, so a target with more rows than that silently lost the
// remainder — and because the fetch was target-wide and filtered afterwards,
// the rows that fell outside the cap could be exactly the ones the rendered
// scan observed. Paging with an advancing OFFSET removes that failure mode.
const reportRowLimit = 10000

// reportMaxRows is the sanity ceiling on ACCUMULATED rows of one kind. Paging
// stops here with a warning so a pathological target cannot exhaust memory in
// silence. It is deliberately an order of magnitude above any realistic
// engagement: hitting it means something is wrong, and the log says so.
const reportMaxRows = 200000

// HistoricalNotice is the marker stamped into a report rendered with
// includeHistorical=true. A report that silently widened its scope from "what
// this scan saw" to "everything this target has ever had" is unattributable
// after the fact (T-15-11-04), so the widening is always visible in the output
// itself, not only in the log.
const HistoricalNotice = "SCOPE WARNING: this report includes historical target-wide assets not observed by this scan"

// pageLimit is the effective page size — SetPageSize lowers it for tests that
// need to exercise the multi-page path without seeding 10 000 rows.
func (r *ReportRenderer) pageLimit() int64 {
	if r.pageSize > 0 {
		return r.pageSize
	}
	return reportRowLimit
}

// SetPageSize overrides the query page size. Zero or negative restores the
// default (reportRowLimit). This is a test/ops seam: pagination that is only
// ever exercised at 10 000 rows is pagination that is never exercised.
func (r *ReportRenderer) SetPageSize(n int64) {
	r.pageSize = n
}

// warnIfTruncated logs when accumulation stopped at the reportMaxRows ceiling.
// The report really is short in that case, and a short report that does not
// say so is the one thing a report must never be.
func (r *ReportRenderer) warnIfTruncated(ctx context.Context, kind string, got int) {
	if int64(got) >= reportMaxRows {
		r.log.WarnContext(ctx, "report: result set hit the sanity ceiling — the report is TRUNCATED",
			"kind", kind, "ceiling", reportMaxRows)
	}
}

// pageAll drains a LIMIT/OFFSET query into one slice of pointers.
//
// Each page is its own backing array, so taking &batch[i] is safe: the pointers
// keep their page alive and no later append can move the element out from under
// them.
func pageAll[T any](
	ctx context.Context,
	r *ReportRenderer,
	kind string,
	fetch func(limit, offset int64) ([]T, error),
) ([]*T, error) {
	limit := r.pageLimit()
	var out []*T
	for offset := int64(0); ; offset += limit {
		batch, err := fetch(limit, offset)
		if err != nil {
			return nil, err
		}
		for i := range batch {
			out = append(out, &batch[i])
		}
		if int64(len(batch)) < limit {
			break // short page — the result set is exhausted
		}
		if int64(len(out)) >= reportMaxRows {
			r.warnIfTruncated(ctx, kind, len(out))
			break
		}
	}
	return out, nil
}

// fetchForScan reads exactly the assets THIS scan recorded in scan_observation,
// by JOIN rather than by fetching the target's history and filtering it.
//
// The deleted fetch-then-filter predecessor treated "this scan observed no rows
// of kind K" as "this scan does not produce kind K" and passed the target's
// whole K inventory through untouched — so a subs-only run emitted every URL
// the target had ever had into a deliverable report (T-15-11-01, F12). There is
// no equivalent state here: a kind with no observations returns no rows.
func (r *ReportRenderer) fetchForScan(ctx context.Context, scanID string) (
	[]*sqlcgen.Finding, []*sqlcgen.Host, []*sqlcgen.URL, error,
) {
	findings, err := pageAll(ctx, r, "findings", func(limit, offset int64) ([]sqlcgen.Finding, error) {
		return r.q.ListFindingsForScan(ctx, sqlcgen.ListFindingsForScanParams{
			ScanID: scanID, Limit: limit, Offset: offset,
		})
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("report: list findings for scan: %w", err)
	}
	hosts, err := pageAll(ctx, r, "hosts", func(limit, offset int64) ([]sqlcgen.Host, error) {
		return r.q.ListHostsForScan(ctx, sqlcgen.ListHostsForScanParams{
			ScanID: scanID, Limit: limit, Offset: offset,
		})
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("report: list hosts for scan: %w", err)
	}
	urls, err := pageAll(ctx, r, "urls", func(limit, offset int64) ([]sqlcgen.URL, error) {
		return r.q.ListURLsForScan(ctx, sqlcgen.ListURLsForScanParams{
			ScanID: scanID, Limit: limit, Offset: offset,
		})
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("report: list urls for scan: %w", err)
	}
	return findings, hosts, urls, nil
}

// fetchHistorical reads the target's ENTIRE asset history, ignoring which scan
// saw what. This is the old behaviour, now reachable only through the explicit
// includeHistorical opt-in and always stamped with HistoricalNotice.
func (r *ReportRenderer) fetchHistorical(ctx context.Context, targetID string) (
	[]*sqlcgen.Finding, []*sqlcgen.Host, []*sqlcgen.URL, error,
) {
	findings, err := pageAll(ctx, r, "findings", func(limit, offset int64) ([]sqlcgen.Finding, error) {
		return r.q.ListFindingsForTarget(ctx, sqlcgen.ListFindingsForTargetParams{
			TargetID: targetID, Limit: limit, Offset: offset,
		})
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("report: list findings for target: %w", err)
	}
	urls, err := pageAll(ctx, r, "urls", func(limit, offset int64) ([]sqlcgen.URL, error) {
		return r.q.ListURLsForTarget(ctx, sqlcgen.ListURLsForTargetParams{
			TargetID: targetID, Limit: limit, Offset: offset,
		})
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("report: list urls for target: %w", err)
	}
	hosts, err := r.pageHostsForTarget(ctx, targetID)
	if err != nil {
		return nil, nil, nil, err
	}
	return findings, hosts, urls, nil
}

// pageHostsForTarget drains ListHostsCursor, which is keyset- rather than
// offset-paginated: the cursor is (last_seen_at, id) descending, exactly the
// ORDER BY the query declares.
func (r *ReportRenderer) pageHostsForTarget(ctx context.Context, targetID string) ([]*sqlcgen.Host, error) {
	limit := r.pageLimit()
	var out []*sqlcgen.Host
	var curSeenAt, curLastID int64
	for {
		batch, err := r.q.ListHostsCursor(ctx, sqlcgen.ListHostsCursorParams{
			TargetID:     targetID,
			CdnFilter:    "",
			CursorSeenAt: curSeenAt,
			CursorLastID: curLastID,
			RowLimit:     limit,
		})
		if err != nil {
			return nil, fmt.Errorf("report: list hosts for target: %w", err)
		}
		for i := range batch {
			out = append(out, &batch[i])
		}
		if int64(len(batch)) < limit {
			break
		}
		last := batch[len(batch)-1]
		// A zero last_seen_at cannot advance the cursor (the query reads ?3 = 0
		// as "no cursor"), so stop rather than loop over the same page forever.
		if last.LastSeenAt == 0 {
			r.warnIfTruncated(ctx, "hosts", len(out))
			break
		}
		curSeenAt, curLastID = last.LastSeenAt, last.ID
		if int64(len(out)) >= reportMaxRows {
			r.warnIfTruncated(ctx, "hosts", len(out))
			break
		}
	}
	return out, nil
}

// RenderAll renders the latest completed scan for targetID, or the explicit
// scanID when given. allowPartial additionally accepts the most recent
// INCOMPLETE scan when no completed one exists — the behaviour --allow-partial
// always advertised while being read by nothing.
//
// Scan resolution order:
//  1. If scanID is non-empty, use GetScan(scanID).
//  2. Otherwise use GetLatestCompletedScanForTarget(targetID).
//
// includeHistorical widens the asset lists from "what this scan observed" to
// "everything this target has ever had". It defaults to false and there is no
// implicit fallback into it: a scan that observed nothing renders an EMPTY
// report, loudly, rather than a target-wide dump wearing one scan's header.
// It returns the RenderResult manifest: the scan, the directory and the exact
// list of files THIS call wrote. Callers report from the manifest instead of
// listing a directory, so a stale file from an earlier run cannot be presented
// as part of this report.
func (r *ReportRenderer) RenderAll(ctx context.Context, targetID, scanID string, allowPartial, includeHistorical bool) (RenderResult, error) {
	var res RenderResult
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
		return res, fmt.Errorf("report: no completed scan found for target %q (%s)", targetID, hint)
	}
	if err != nil {
		return res, fmt.Errorf("report: get scan: %w", err)
	}

	// An explicit --scan-id bypassed the completed-scan requirement entirely, so
	// `report --scan-id <running scan>` rendered a half-finished run as a
	// finished assessment while --allow-partial — the flag whose entire purpose
	// is to opt into that — sat unread. Apply the same rule to both paths.
	if !allowPartial && scan.Status != "completed" {
		return res, fmt.Errorf(
			"report: scan %s is %q, not completed — pass --allow-partial to render it anyway",
			scan.ID, scan.Status)
	}

	// The resolved scan is the authority on which target this report describes.
	// An explicit --scan-id was never checked against the target argument, so
	// `report --target A --scan-id <a scan of B>` rendered B's scan header over
	// A's findings, hosts and URLs — a report that looks authoritative and
	// describes an asset the scan never touched. Refuse rather than guess.
	if targetID != "" && scan.TargetID != targetID {
		return res, fmt.Errorf(
			"report: scan %s belongs to target %q, not %q — refusing to render a "+
				"report mixing one scan's header with another target's data",
			scan.ID, scan.TargetID, targetID)
	}
	// With no --target the scan supplies it, so every query below is scoped to
	// the scan's own target rather than to whatever the caller passed.
	targetID = scan.TargetID

	r.log.InfoContext(ctx, "report: rendering scan", "scan_id", scan.ID, "target", scan.TargetID)

	// Step 2: fetch the assets to render.
	//
	// Per-scan by default: every list below comes from a JOIN over this scan's
	// scan_observation rows, so "the scan saw none of these" and "this scan mode
	// does not produce these" render identically — as nothing. The target-wide
	// lists are reachable only through the explicit opt-in.
	var (
		findings []*sqlcgen.Finding
		hosts    []*sqlcgen.Host
		urls     []*sqlcgen.URL
	)
	historicalNotice := ""
	if includeHistorical {
		findings, hosts, urls, err = r.fetchHistorical(ctx, targetID)
		if err != nil {
			return res, err
		}
		historicalNotice = HistoricalNotice
		r.log.WarnContext(ctx, "report: "+HistoricalNotice,
			"scan_id", scan.ID, "target", targetID,
			"findings", len(findings), "hosts", len(hosts), "urls", len(urls))
	} else {
		findings, hosts, urls, err = r.fetchForScan(ctx, scan.ID)
		if err != nil {
			return res, err
		}
		if len(findings) == 0 && len(hosts) == 0 && len(urls) == 0 {
			// Not a fallback trigger. A run that found nothing MUST render an
			// empty report — that is acceptance gate 3's second clause, and
			// substituting the target's history here would resurrect findings
			// the operator has already remediated.
			r.log.WarnContext(ctx, "report: scan recorded no observations — rendering an EMPTY report "+
				"(pass --include-historical for the target's full asset history)",
				"scan_id", scan.ID, "target", targetID)
		}
		r.log.InfoContext(ctx, "report: scoped to this scan's observations",
			"scan_id", scan.ID,
			"findings", len(findings), "hosts", len(hosts), "urls", len(urls))
	}

	// Step 3: resolve and create THIS scan's report directory.
	//
	// reports/<target-slug>/<scan-id>/ replaces the single shared reports/ dir.
	// In the shared directory a run inherited whatever the previous run left
	// behind — a Faraday export written when the integration was enabled, an AI
	// report from before AI was turned off — and every consumer, including the
	// MCP tool, presented those files as part of the current report
	// (T-15-11-03). A per-scan directory has nothing to inherit.
	//
	// The slug is output.CanonicalTargetID's, the same identity the workspace
	// tree uses, so the two trees address a target the same way (15-01).
	ident, idErr := output.CanonicalTargetID(scan.TargetID)
	if idErr != nil {
		return res, fmt.Errorf("report: canonical target id for %q: %w", scan.TargetID, idErr)
	}
	targetReportsDir := filepath.Join(r.workDir, "reports", ident.Slug)
	reportsDir := filepath.Join(targetReportsDir, scan.ID)
	if err := os.MkdirAll(reportsDir, 0o755); err != nil {
		return res, fmt.Errorf("report: mkdir reports: %w", err)
	}
	res = RenderResult{
		ScanID:            scan.ID,
		TargetID:          scan.TargetID,
		Dir:               reportsDir,
		IncludeHistorical: includeHistorical,
		Notice:            historicalNotice,
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
		ScopeNotice:     historicalNotice,
	}

	htmlPath := filepath.Join(reportsDir, "report.html")
	if err := RenderHTML(htmlData, htmlPath); err != nil {
		return res, fmt.Errorf("report: html: %w", err)
	}
	res.add(htmlPath)
	r.log.InfoContext(ctx, "report: wrote HTML report", "path", htmlPath)

	// Step 5: write CSV files.
	if err := WriteAllCSV(reportsDir, findings, hosts, urls); err != nil {
		return res, fmt.Errorf("report: csv: %w", err)
	}
	for _, name := range csvFileNames {
		res.add(filepath.Join(reportsDir, name))
	}

	// Step 6: write SARIF.
	sarifPath := filepath.Join(reportsDir, "findings.sarif")
	if err := WriteSARIF(sarifPath, version, findings); err != nil {
		return res, fmt.Errorf("report: sarif: %w", err)
	}
	res.add(sarifPath)

	// Step 7: write hotlist JSON.
	hotlistPath := filepath.Join(reportsDir, "hotlist.json")
	if err := WriteHotlist(hotlistPath, hotlistItems); err != nil {
		return res, fmt.Errorf("report: hotlist: %w", err)
	}
	res.add(hotlistPath)

	// Step 8: write Faraday export (gated on Integrations.Faraday.Enabled).
	//
	// Only a SUCCESSFUL write is recorded: the manifest states what exists, and
	// a best-effort export that failed does not.
	if r.cfg != nil && r.cfg.Integrations.Faraday.Enabled {
		faradayPath := filepath.Join(reportsDir, "faraday.json")
		if err := WriteFaraday(faradayPath, findings, hosts); err != nil {
			r.log.WarnContext(ctx, "report: faraday export failed (non-fatal)", "err", err)
		} else {
			res.add(faradayPath)
			r.log.InfoContext(ctx, "report: wrote Faraday export", "path", faradayPath)
		}
	}

	// Step 9: write notes.jsonl (canonical REPORT-01 artefact — always written).
	if err := WriteNotesJSONL(reportsDir); err != nil {
		return res, fmt.Errorf("report: notes.jsonl: %w", err)
	}
	res.add(filepath.Join(reportsDir, "notes.jsonl"))

	// Step 9b: the historical-scope marker, when the report was widened. The
	// HTML banner covers a human reader; this covers a consumer that only reads
	// the machine formats.
	if includeHistorical {
		markerPath := filepath.Join(reportsDir, HistoricalMarkerName)
		if err := output.WriteFile(markerPath, []byte(HistoricalNotice+"\n"), 0o644); err != nil {
			return res, fmt.Errorf("report: historical marker: %w", err)
		}
		res.add(markerPath)
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
					res.add(aiPath)
					r.log.InfoContext(ctx, "report: wrote AI report", "path", aiPath)
				}
			}
		}
	}

	// Step 11: the manifest, then the per-target latest pointer.
	//
	// manifest.json is deliberately absent from res.Files: Files is the report,
	// the manifest describes it. Writing the pointer last means it only ever
	// names a directory whose manifest is already on disk.
	res.finalise()
	if err := WriteRenderManifest(&res); err != nil {
		return res, fmt.Errorf("report: manifest: %w", err)
	}
	if err := WriteLatestPointer(targetReportsDir, &res); err != nil {
		return res, fmt.Errorf("report: latest pointer: %w", err)
	}
	r.log.InfoContext(ctx, "report: render complete",
		"scan_id", res.ScanID, "dir", res.Dir, "files", len(res.Files))

	return res, nil
}

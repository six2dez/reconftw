// Package ingest bridges the scan pipeline's JSONL artefacts into the queryable
// SQLite store (store.db) that report / SARIF / hotlist / AI / faraday / monitor
// all read from.
//
// Before this package existed the pipeline wrote only JSONL under
// <workDir>/artefacts/, while every consumer read <dataDir>/store.db — which
// nothing populated, so `reconftw report` failed with "no completed scan found".
// ScanIntoStore closes that gap: after the pipeline's final merge it opens the
// shared store, records a completed scan, and upserts hosts/urls/findings linked
// to the target using the queries that already existed in internal/store/sqlc.
//
// It is deliberately decoupled (takes plain strings, not *appctx.AppContext) so
// it imports no orchestration packages and is trivially unit-testable.
package ingest

import (
	"bufio"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	// modernc.org/sqlite registers the "sqlite" driver name (pure-Go, CGO-free).
	_ "modernc.org/sqlite"

	sqlcgen "github.com/six2dez/reconftw/internal/store/sqlc"
)

// maxJSONLLine bounds a single artefact record; nuclei/dalfox findings can be
// large, so allow up to 8 MiB before skipping an over-long line.
const maxJSONLLine = 8 << 20

// Result summarises what a ScanIntoStore call persisted.
type Result struct {
	ScanID   string
	Findings int
	Hosts    int
	URLs     int
}

// ScanIntoStore ingests the merged JSONL artefacts under workDir/artefacts into
// the shared store at dataDir/store.db and records a completed scan row for
// target. mode is the scan mode label ("recon", "all", "web", ...).
//
// It is best-effort per record — malformed lines and missing artefact files are
// skipped (logged at debug), never fatal. It returns an error only when the
// store itself cannot be opened / initialised or the scan row cannot be created,
// so callers can safely log-and-continue.
func ScanIntoStore(ctx context.Context, dataDir, workDir, target, mode string, logger *slog.Logger) (Result, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if dataDir == "" {
		dataDir = "data"
	}

	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return Result{}, fmt.Errorf("ingest: mkdir data dir: %w", err)
	}
	storePath := filepath.Join(dataDir, "store.db")
	dsn := storePath + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return Result{}, fmt.Errorf("ingest: open store: %w", err)
	}
	defer db.Close() //nolint:errcheck

	if err := sqlcgen.EnsureSchema(ctx, db); err != nil {
		return Result{}, fmt.Errorf("ingest: ensure schema: %w", err)
	}

	q := sqlcgen.New(db)
	now := time.Now().Unix()

	if err := ensureTarget(ctx, q, target, workDir, now); err != nil {
		return Result{}, fmt.Errorf("ingest: ensure target: %w", err)
	}

	scanID := uuid.New().String()
	if _, err := q.CreateScan(ctx, sqlcgen.CreateScanParams{
		ID:                  scanID,
		TargetID:            target,
		Mode:                mode,
		Status:              "running",
		StartedAt:           now,
		RawArgsJson:         "{}",
		ConfigOverridesJson: "{}",
		OutputDir:           workDir,
	}); err != nil {
		return Result{}, fmt.Errorf("ingest: create scan: %w", err)
	}

	artefacts := filepath.Join(workDir, "artefacts")

	hostIDs := ingestHosts(ctx, q, scanID, target, artefacts, now, logger)
	urlCount := ingestURLs(ctx, q, scanID, target, artefacts, hostIDs, now, logger)
	findingCount := ingestFindings(ctx, q, scanID, target, artefacts, hostIDs, now, logger)

	if err := q.UpdateScanCounts(ctx, sqlcgen.UpdateScanCountsParams{
		FindingsCount:  int64(findingCount),
		SubdomainCount: int64(len(hostIDs)),
		UrlCount:       int64(urlCount),
		ID:             scanID,
	}); err != nil {
		logger.WarnContext(ctx, "ingest: update scan counts failed", "err", err)
	}

	finished := time.Now().Unix()
	if err := q.UpdateScanStatus(ctx, sqlcgen.UpdateScanStatusParams{
		Status:     "completed",
		FinishedAt: &finished,
		ID:         scanID,
	}); err != nil {
		return Result{}, fmt.Errorf("ingest: mark scan completed: %w", err)
	}

	res := Result{ScanID: scanID, Findings: findingCount, Hosts: len(hostIDs), URLs: urlCount}
	logger.InfoContext(ctx, "ingest: scan persisted to store",
		"scan_id", scanID, "target", target, "mode", mode,
		"findings", res.Findings, "hosts", res.Hosts, "urls", res.URLs, "store", storePath)
	return res, nil
}

// ensureTarget makes sure a target row exists (CreateTarget errors on a
// duplicate id — the store is shared across runs, so a second scan finds the row
// already present, which is not an error).
func ensureTarget(ctx context.Context, q *sqlcgen.Queries, target, workDir string, now int64) error {
	if _, err := q.GetTarget(ctx, target); err == nil {
		return nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	_, err := q.CreateTarget(ctx, sqlcgen.CreateTargetParams{
		ID:       target,
		Name:     target,
		ReconDir: workDir,
		TagsJson: "[]",
		Now:      now,
	})
	// A concurrent/previous run may have created it between GetTarget and here.
	if err != nil {
		if _, gerr := q.GetTarget(ctx, target); gerr == nil {
			return nil
		}
		return err
	}
	return nil
}

// hostRecord is the union of subdomains.HostRecord and web.HostRecord — omitempty
// on both producers means one struct unmarshals either shape.
type hostRecord struct {
	Host string `json:"host"`
	IP   string `json:"ip"`
	CDN  string `json:"cdn"`
}

// ingestHosts upserts every host in hosts.jsonl + subdomains.jsonl and links it
// to the target. Returns fqdn → host id for finding/url linkage. It also records
// a per-scan scan_observation row for each host so the cross-cycle diff queries
// (DiffScansHosts) can see what this scan observed (INTEG-04). The ids[fqdn]
// guard ensures each unique host is observed exactly once per scan.
func ingestHosts(ctx context.Context, q *sqlcgen.Queries, scanID, target, artefacts string, now int64, logger *slog.Logger) map[string]int64 {
	ids := make(map[string]int64)
	for _, name := range []string{"hosts.jsonl", "subdomains.jsonl"} {
		forEachJSONL(filepath.Join(artefacts, name), logger, func(line []byte) {
			var rec hostRecord
			if err := json.Unmarshal(line, &rec); err != nil {
				return
			}
			fqdn := strings.TrimSpace(rec.Host)
			if fqdn == "" || ids[fqdn] != 0 {
				return
			}
			host, err := q.UpsertHost(ctx, sqlcgen.UpsertHostParams{
				FQDN:      fqdn,
				IpCurrent: ptrIfSet(rec.IP),
				CDN:       ptrIfSet(rec.CDN),
				Now:       now,
			})
			if err != nil {
				logger.DebugContext(ctx, "ingest: upsert host failed", "fqdn", fqdn, "err", err)
				return
			}
			ids[fqdn] = host.ID
			if err := q.AttachHostToTarget(ctx, sqlcgen.AttachHostToTargetParams{
				TargetID: target, HostID: host.ID,
			}); err != nil {
				logger.DebugContext(ctx, "ingest: attach host failed", "fqdn", fqdn, "err", err)
			}
			recordObservation(ctx, q, scanID, target, "host", host.ID, now, logger)
		})
	}
	return ids
}

// urlRecord mirrors internal/extract/urls.URLRecord (the urls.jsonl shape).
type urlRecord struct {
	URL  string `json:"url"`
	Host string `json:"host"`
}

func ingestURLs(ctx context.Context, q *sqlcgen.Queries, scanID, target, artefacts string, hostIDs map[string]int64, now int64, logger *slog.Logger) int {
	count := 0
	// seen dedups scan_observation inserts when two artefact lines resolve to the
	// same upserted URL row (UpsertURL ON CONFLICT by url_hash) — the same scan
	// must not observe the same asset twice (INTEG-04).
	seen := make(map[int64]struct{})
	forEachJSONL(filepath.Join(artefacts, "urls.jsonl"), logger, func(line []byte) {
		var rec urlRecord
		if err := json.Unmarshal(line, &rec); err != nil || strings.TrimSpace(rec.URL) == "" {
			return
		}
		u, perr := url.Parse(rec.URL)
		if perr != nil {
			return
		}
		sum := sha256.Sum256([]byte(rec.URL))
		params := sqlcgen.UpsertURLParams{
			URL:            rec.URL,
			UrlHash:        sum[:],
			Scheme:         u.Scheme,
			Path:           u.Path,
			QueryCanonical: u.RawQuery,
			Now:            now,
		}
		host := rec.Host
		if host == "" {
			host = u.Hostname()
		}
		if id, ok := hostIDs[host]; ok {
			params.HostID = &id
		}
		row, err := q.UpsertURL(ctx, params)
		if err != nil {
			logger.DebugContext(ctx, "ingest: upsert url failed", "url", rec.URL, "err", err)
			return
		}
		if err := q.AttachURLToTarget(ctx, sqlcgen.AttachURLToTargetParams{
			TargetID: target, URLID: row.ID,
		}); err != nil {
			logger.DebugContext(ctx, "ingest: attach url failed", "url", rec.URL, "err", err)
		}
		if _, dup := seen[row.ID]; !dup {
			seen[row.ID] = struct{}{}
			recordObservation(ctx, q, scanID, target, "url", row.ID, now, logger)
		}
		count++
	})
	return count
}

// findingRecord is the union of the three per-domain finding shapes:
// web.FindingRecord, vulns.VulnFindingRecord, osint.OSINTFindingRecord. All use
// omitempty, so a single struct with every field unmarshals any of them.
type findingRecord struct {
	Severity string `json:"severity"`
	// web.FindingRecord
	Type        string `json:"type"`
	Host        string `json:"host"`
	TemplateID  string `json:"template_id"`
	MatcherName string `json:"matcher_name"`
	MatchedAt   string `json:"matched_at"`
	Service     string `json:"service"`
	// vulns.VulnFindingRecord
	VulnClass    string `json:"vuln_class"`
	MatchedParam string `json:"matched_param"`
	Engine       string `json:"engine"`
	// osint.OSINTFindingRecord
	Class    string `json:"class"`
	Source   string `json:"source"`
	Category string `json:"category"`
}

func ingestFindings(ctx context.Context, q *sqlcgen.Queries, scanID, target, artefacts string, hostIDs map[string]int64, now int64, logger *slog.Logger) int {
	count := 0
	// seen dedups scan_observation inserts when two artefact lines resolve to the
	// same upserted finding row (UpsertFinding ON CONFLICT) — the same scan must
	// not observe the same asset twice (INTEG-04).
	seen := make(map[int64]struct{})
	forEachJSONL(filepath.Join(artefacts, "findings.jsonl"), logger, func(line []byte) {
		var rec findingRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			return
		}
		sig := firstNonEmpty(rec.TemplateID, rec.VulnClass, joinNonEmpty("/", rec.Source, rec.Category), rec.MatcherName)
		if sig == "" {
			return // nothing identifiable to key on
		}
		params := sqlcgen.UpsertFindingParams{
			TemplateSignature: sig,
			Tool:              firstNonEmpty(rec.Engine, rec.Service, rec.Type, rec.Source, "reconftw"),
			Severity:          normalizeSeverity(rec.Severity),
			Title:             firstNonEmpty(rec.MatcherName, rec.VulnClass, rec.Category, rec.TemplateID, sig),
			MatchedAt:         firstNonEmpty(rec.MatchedAt, rec.MatchedParam),
			Now:               now,
		}
		if id, ok := hostIDs[rec.Host]; ok {
			params.HostID = &id
		}
		row, err := q.UpsertFinding(ctx, params)
		if err != nil {
			logger.DebugContext(ctx, "ingest: upsert finding failed", "sig", sig, "err", err)
			return
		}
		if err := q.AttachFindingToTarget(ctx, sqlcgen.AttachFindingToTargetParams{
			TargetID: target, FindingID: row.ID,
		}); err != nil {
			logger.DebugContext(ctx, "ingest: attach finding failed", "sig", sig, "err", err)
			return
		}
		if _, dup := seen[row.ID]; !dup {
			seen[row.ID] = struct{}{}
			recordObservation(ctx, q, scanID, target, "finding", row.ID, now, logger)
		}
		count++
	})
	return count
}

// recordObservation writes a scan_observation row linking an asset (host/url/
// finding) to this scan. The cross-cycle diff queries (DiffScansHosts /
// DiffScansURLs / DiffScansFindings) read EXCLUSIVELY from scan_observation, so
// without this the monitor diff is silently empty even against a fully populated
// store (INTEG-04). Best-effort: any failure is logged at debug and never aborts
// ingest — the JSONL artefacts remain the source of truth.
func recordObservation(ctx context.Context, q *sqlcgen.Queries, scanID, target, kind string, assetID, now int64, logger *slog.Logger) {
	if err := q.InsertObservation(ctx, sqlcgen.InsertObservationParams{
		ScanID:     scanID,
		TargetID:   target,
		AssetKind:  kind,
		AssetID:    assetID,
		ObservedAt: now,
		RawJson:    nil,
	}); err != nil {
		logger.DebugContext(ctx, "ingest: insert observation failed",
			"kind", kind, "asset_id", assetID, "err", err)
	}
}

// forEachJSONL calls fn for every non-blank line of a JSONL file. A missing file
// is silently skipped (an absent artefact just means that pipeline did not run).
func forEachJSONL(path string, logger *slog.Logger, fn func(line []byte)) {
	f, err := os.Open(path) //nolint:gosec // path built from workDir, not user input
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) && logger != nil {
			logger.Debug("ingest: open artefact failed", "path", path, "err", err)
		}
		return
	}
	defer f.Close() //nolint:errcheck

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), maxJSONLLine)
	for sc.Scan() {
		line := sc.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		// Copy: Scanner reuses its buffer across iterations.
		cp := make([]byte, len(line))
		copy(cp, line)
		fn(cp)
	}
}

func ptrIfSet(s string) *string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return &s
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func joinNonEmpty(sep string, vals ...string) string {
	kept := make([]string, 0, len(vals))
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			kept = append(kept, v)
		}
	}
	return strings.Join(kept, sep)
}

// normalizeSeverity coerces arbitrary producer severity strings to the store's
// canonical ladder, defaulting unknown/empty to "info".
func normalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	case "informational", "info":
		return "info"
	default:
		return "info"
	}
}

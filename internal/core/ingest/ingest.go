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
	"sort"
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

// Scan terminal states. The store's status column is free-form text, so these
// constants are the one place ingest's vocabulary is defined.
//
//   - statusRunning is written inside the transaction, before any asset row.
//   - statusCompleted means every record the artefacts offered reached the
//     store. It is only ever written INSIDE the transaction that wrote those
//     rows, and only when zero writes were rejected. Every downstream consumer
//     (report baselines, monitor diffs, SARIF, AI) reads 'completed' as "this
//     data is whole", so stamping it on a partial ingest is a security-relevant
//     false negative: the operator sees a short findings list and concludes the
//     target is clean.
//   - statusIncomplete means the rows ARE committed but at least one write was
//     rejected. It is a truthful terminal state, not a synonym for success:
//     GetLatestCompletedScanForTarget filters on 'completed', so an incomplete
//     scan can never be picked as a report or monitor-diff baseline.
//
// There is deliberately no 'failed' row written from here. When the transaction
// itself is unusable nothing is committed, so no scan row exists at all — see
// scanIntoStoreWithDB.
const (
	statusRunning    = "running"
	statusCompleted  = "completed"
	statusIncomplete = "incomplete"
)

// dbFailures accumulates writes the STORE rejected.
//
// That is deliberately not the same thing as bad input, and conflating the two
// would let one junk artefact line fail an otherwise good scan:
//
//   - a malformed / unparseable / absent artefact record is skipped at Debug
//     level and is NOT a failure — ingest stays best-effort about its input;
//   - a rejected database write is recorded here, because the scan can no
//     longer honestly claim to hold everything the pipeline found.
type dbFailures struct {
	n     int
	first error
}

// record notes a rejected write. A nil error is ignored so call sites can pass
// a result straight through.
func (f *dbFailures) record(err error) {
	if err == nil {
		return
	}
	f.n++
	if f.first == nil {
		f.first = err
	}
}

// ScanIntoStore ingests the merged JSONL artefacts under workDir/artefacts into
// the shared store at dataDir/store.db and records a scan row for target. mode
// is the scan mode label ("recon", "all", "web", ...).
//
// Every asset write happens in ONE transaction, so a concurrent reader never
// sees a half-ingested scan and a failure part-way through leaves nothing
// behind — not even the scan row. The returned error therefore now also reports
// a scan that persisted only partially (status 'incomplete'); Result is still
// populated in that case so a caller can notify on what did land.
//
// It stays best-effort about its INPUT: malformed lines and missing artefact
// files are skipped (logged at debug), never fatal. Callers (see
// internal/mcp/handlers/common.go) are expected to keep logging and continuing —
// the transaction fails the scan STATUS, not the scan run.
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
	// _txlock=immediate: the ingest transaction is a writer from its first
	// statement. A deferred transaction takes a read lock and then tries to
	// upgrade on its first write, which two concurrent ingests of two different
	// targets against this one shared file can deadlock on — SQLITE_BUSY on an
	// upgrade is not retryable by busy_timeout, one of the two has to abort.
	// Same reasoning as the BEGIN IMMEDIATE the migration runner takes.
	dsn := storePath + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return Result{}, fmt.Errorf("ingest: open store: %w", err)
	}
	defer db.Close() //nolint:errcheck

	// Schema migration is NOT part of the data transaction: it takes its own
	// dedicated connection under BEGIN IMMEDIATE (internal/store/sqlc/migrate.go)
	// precisely so a concurrent ingest cannot be destroyed by it.
	if err := sqlcgen.EnsureSchema(ctx, db); err != nil {
		return Result{}, fmt.Errorf("ingest: ensure schema: %w", err)
	}

	return scanIntoStoreWithDB(ctx, db, nil, storePath, workDir, target, mode, logger)
}

// scanIntoStoreWithDB performs the whole ingest in ONE transaction against an
// already-opened, already-migrated store.
//
// wrapTx is nil in production — ScanIntoStore passes nil. The tests pass a
// wrapper that fails the Nth statement, which is the only way to prove "an
// injected failure part-way through leaves no completed scan and no partial
// rows" against a real on-disk database rather than against a mock. It is
// unexported, adds no hook to the public API and reads no package-level state,
// so it cannot alter production behaviour.
func scanIntoStoreWithDB(ctx context.Context, db *sql.DB, wrapTx func(sqlcgen.DBTX) sqlcgen.DBTX,
	storePath, workDir, target, mode string, logger *slog.Logger,
) (Result, error) {
	if logger == nil {
		logger = slog.Default()
	}
	now := time.Now().Unix()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return Result{}, fmt.Errorf("ingest: begin transaction: %w", err)
	}
	// Every early return below discards the scan row together with the rows it
	// would have claimed to describe. Nothing marks a scan completed outside the
	// transaction that wrote them.
	defer func() { _ = tx.Rollback() }()

	qtx := sqlcgen.New(db).WithTx(tx)
	if wrapTx != nil {
		qtx = sqlcgen.New(wrapTx(tx))
	}

	if err := ensureTarget(ctx, qtx, target, workDir, now); err != nil {
		return Result{}, fmt.Errorf("ingest: ensure target: %w", err)
	}

	scanID := uuid.New().String()
	if _, err := qtx.CreateScan(ctx, sqlcgen.CreateScanParams{
		ID:                  scanID,
		TargetID:            target,
		Mode:                mode,
		Status:              statusRunning,
		StartedAt:           now,
		RawArgsJson:         "{}",
		ConfigOverridesJson: "{}",
		OutputDir:           workDir,
	}); err != nil {
		return Result{}, fmt.Errorf("ingest: create scan: %w", err)
	}

	artefacts := filepath.Join(workDir, "artefacts")

	var fails dbFailures
	hostIDs := ingestHosts(ctx, qtx, scanID, target, artefacts, now, logger, &fails)
	ingestURLs(ctx, qtx, scanID, target, artefacts, hostIDs, now, logger, &fails)
	ingestFindings(ctx, qtx, scanID, target, artefacts, hostIDs, now, logger, &fails)

	// Counters are read back out of the transaction, so they describe rows that
	// exist — never input lines. A line that failed to upsert, or that
	// deduplicated onto a row this scan already observed, is not a discovery:
	// counting lines reports more findings than the store holds and yields a
	// report that cannot be reconciled against the store it came from.
	hosts, err := observedCount(ctx, qtx, scanID, "host")
	if err != nil {
		return Result{}, err
	}
	urls, err := observedCount(ctx, qtx, scanID, "url")
	if err != nil {
		return Result{}, err
	}
	findings, err := observedCount(ctx, qtx, scanID, "finding")
	if err != nil {
		return Result{}, err
	}

	if err := qtx.UpdateScanCounts(ctx, sqlcgen.UpdateScanCountsParams{
		FindingsCount:  findings,
		SubdomainCount: hosts,
		UrlCount:       urls,
		ID:             scanID,
	}); err != nil {
		// No longer a warning: the counts are part of the scan row, so a
		// rejected update means the scan is not persisted correctly.
		return Result{}, fmt.Errorf("ingest: update scan counts: %w", err)
	}

	status := statusCompleted
	if fails.n > 0 {
		status = statusIncomplete
	}
	finished := time.Now().Unix()
	if err := qtx.UpdateScanStatus(ctx, sqlcgen.UpdateScanStatusParams{
		Status:     status,
		FinishedAt: &finished,
		ID:         scanID,
	}); err != nil {
		return Result{}, fmt.Errorf("ingest: mark scan %s: %w", status, err)
	}

	if err := tx.Commit(); err != nil {
		return Result{}, fmt.Errorf("ingest: commit scan: %w", err)
	}

	res := Result{ScanID: scanID, Findings: int(findings), Hosts: int(hosts), URLs: int(urls)}
	logger.InfoContext(ctx, "ingest: scan persisted to store",
		"scan_id", scanID, "target", target, "mode", mode, "status", status,
		"findings", res.Findings, "hosts", res.Hosts, "urls", res.URLs, "store", storePath)
	if fails.n > 0 {
		// The rows ARE committed and Result is populated, so the caller can
		// still notify on what landed; the error says the scan is not whole.
		return res, fmt.Errorf("ingest: scan %s recorded as %s: %d record(s) rejected by the store: %w",
			scanID, status, fails.n, fails.first)
	}
	return res, nil
}

// observedCount reports how many assets of one kind this scan actually
// committed, counted in scan_observation from inside the ingest transaction.
func observedCount(ctx context.Context, q *sqlcgen.Queries, scanID, kind string) (int64, error) {
	n, err := q.CountObservationsForScanByKind(ctx, sqlcgen.CountObservationsForScanByKindParams{
		ScanID:    scanID,
		AssetKind: kind,
	})
	if err != nil {
		return 0, fmt.Errorf("ingest: count %s observations: %w", kind, err)
	}
	return n, nil
}

// ensureTarget makes sure a target row exists and that its recon_dir names THIS
// run's workspace.
//
// The refresh is unconditional, and deliberately so. CreateTarget only writes
// recon_dir when it creates the row, so a target scanned a second time with a
// different --output kept pointing at the first run's directory forever and
// every reader that resolves artefacts through targets.recon_dir read an older
// engagement's tree. It is also the repair path for plan 15-01's workspace
// rename: that plan moved every existing workspace onto the new canonical slug,
// which left the recon_dir values already in store.db pointing at paths that no
// longer exist. Each target is repaired by its next ingest. A "skip when
// unchanged" optimisation would be one branch away from never repairing them.
func ensureTarget(ctx context.Context, q *sqlcgen.Queries, target, workDir string, now int64) error {
	if err := createTargetIfAbsent(ctx, q, target, workDir, now); err != nil {
		return err
	}
	return q.UpdateTargetReconDir(ctx, sqlcgen.UpdateTargetReconDirParams{
		ReconDir: workDir,
		Now:      now,
		ID:       target,
	})
}

// createTargetIfAbsent creates the target row when it is missing (CreateTarget
// errors on a duplicate id — the store is shared across runs, so a second scan
// finds the row already present, which is not an error).
func createTargetIfAbsent(ctx context.Context, q *sqlcgen.Queries, target, workDir string, now int64) error {
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

// hostRecord decodes artefacts/hosts.jsonl. Both writers of that artefact
// (web.HostRecord and subdomains.HostRecord, the geo enrichment shape) key the
// hostname on "host", so one struct covers both.
//
// It does NOT cover artefacts/subdomains.jsonl — see subdomainRecord.
type hostRecord struct {
	Host string `json:"host"`
	IP   string `json:"ip"`
	CDN  string `json:"cdn"`
}

// subdomainRecord decodes artefacts/subdomains.jsonl, which
// subdomains.MergeStage writes as {"subdomain","source","first_seen"} —
// NOT {"host"}.
//
// Both files used to be decoded with hostRecord, so every subdomain line
// unmarshalled to an empty Host and was skipped: the store received nothing
// from the single largest artefact in the tree. The unit test hid it by
// fabricating a subdomains.jsonl full of {"host":…} lines, a shape no
// producer emits — the fixture encoded the bug instead of catching it.
type subdomainRecord struct {
	Subdomain string `json:"subdomain"`
	Source    string `json:"source"`
}

// fqdn returns the hostname carried by a subdomains.jsonl line.
func (r subdomainRecord) fqdn() string { return strings.TrimSpace(r.Subdomain) }

// ingestHosts upserts every host in hosts.jsonl + subdomains.jsonl and links it
// to the target. Returns fqdn → host id for finding/url linkage. It also records
// a per-scan scan_observation row for each host so the cross-cycle diff queries
// (DiffScansHosts) can see what this scan observed (INTEG-04). The ids[fqdn]
// guard ensures each unique host is observed exactly once per scan.
//
// A line that does not decode is skipped and is NOT counted in fails: bad input
// must never fail an otherwise good scan. A write the store rejects IS counted,
// because the scan then holds less than the artefacts offered.
func ingestHosts(ctx context.Context, q *sqlcgen.Queries, scanID, target, artefacts string, now int64, logger *slog.Logger, fails *dbFailures) map[string]int64 {
	ids := make(map[string]int64)

	// Each artefact gets the decoder for ITS schema. hosts.jsonl keys the
	// hostname on "host"; subdomains.jsonl keys it on "subdomain".
	sources := []struct {
		file   string
		decode func([]byte) (fqdn, ip, cdn string, ok bool)
	}{
		{
			file: "hosts.jsonl",
			decode: func(line []byte) (string, string, string, bool) {
				var rec hostRecord
				if err := json.Unmarshal(line, &rec); err != nil {
					return "", "", "", false
				}
				return strings.TrimSpace(rec.Host), rec.IP, rec.CDN, true
			},
		},
		{
			file: "subdomains.jsonl",
			decode: func(line []byte) (string, string, string, bool) {
				var rec subdomainRecord
				if err := json.Unmarshal(line, &rec); err != nil {
					return "", "", "", false
				}
				// subdomains.jsonl carries no IP or CDN; hosts.jsonl enriches
				// those for the hosts that were probed.
				return rec.fqdn(), "", "", true
			},
		},
	}

	for _, src := range sources {
		forEachJSONL(filepath.Join(artefacts, src.file), logger, func(line []byte) {
			fqdn, recIP, recCDN, ok := src.decode(line)
			if !ok {
				return
			}
			if fqdn == "" || ids[fqdn] != 0 {
				return
			}
			host, err := q.UpsertHost(ctx, sqlcgen.UpsertHostParams{
				FQDN:      fqdn,
				IpCurrent: ptrIfSet(recIP),
				CDN:       ptrIfSet(recCDN),
				Now:       now,
			})
			if err != nil {
				logger.DebugContext(ctx, "ingest: upsert host failed", "fqdn", fqdn, "err", err)
				fails.record(fmt.Errorf("upsert host %q: %w", fqdn, err))
				return
			}
			ids[fqdn] = host.ID
			if err := q.AttachHostToTarget(ctx, sqlcgen.AttachHostToTargetParams{
				TargetID: target, HostID: host.ID,
			}); err != nil {
				logger.DebugContext(ctx, "ingest: attach host failed", "fqdn", fqdn, "err", err)
				fails.record(fmt.Errorf("attach host %q: %w", fqdn, err))
			}
			recordObservation(ctx, q, scanID, target, "host", host.ID, now, logger, fails)
		})
	}
	return ids
}

// urlRecord mirrors internal/extract/urls.URLRecord (the urls.jsonl shape).
type urlRecord struct {
	URL  string `json:"url"`
	Host string `json:"host"`
}

// ingestURLs upserts every URL in urls.jsonl, links it to the target and
// observes it once per scan. It returns nothing: the scan's URL counter is read
// back out of scan_observation, not accumulated from input lines.
func ingestURLs(ctx context.Context, q *sqlcgen.Queries, scanID, target, artefacts string, hostIDs map[string]int64, now int64, logger *slog.Logger, fails *dbFailures) {
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
			fails.record(fmt.Errorf("upsert url: %w", err))
			return
		}
		if err := q.AttachURLToTarget(ctx, sqlcgen.AttachURLToTargetParams{
			TargetID: target, URLID: row.ID,
		}); err != nil {
			logger.DebugContext(ctx, "ingest: attach url failed", "url", rec.URL, "err", err)
			fails.record(fmt.Errorf("attach url: %w", err))
		}
		if _, dup := seen[row.ID]; !dup {
			seen[row.ID] = struct{}{}
			recordObservation(ctx, q, scanID, target, "url", row.ID, now, logger, fails)
		}
	})
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
	// URL is the vulns locator (vulns.VulnFindingRecord.URL) and the web
	// producers' url field. Together with MatchedAt it supplies the per-finding
	// path used for identity — see findingPath.
	URL string `json:"url"`
}

// findingPath derives the location component of a finding's identity.
//
// The findings unique key is (template_signature, tool, host_id, port_id,
// path), and ingest always passed path = "". Every finding of one class on one
// host therefore collapsed into a single row: two distinct SQL injections, on
// two different endpoints or two different parameters of the same host, became
// one finding and one of them vanished from the store.
//
// The path is normalised — scheme, host and fragment dropped, query keys sorted
// and their VALUES discarded — so it identifies the vulnerable location without
// carrying payloads or secrets into the database (XCUT-07). Query keys are kept
// because ?id= and ?user= on the same path are genuinely different findings.
func findingPath(rec findingRecord) string {
	raw := firstNonEmpty(rec.URL, rec.MatchedAt)
	if raw == "" {
		// No locator: fall back to the matched parameter, which several vulns
		// producers use to carry the affected field name.
		return rec.MatchedParam
	}
	u, err := url.Parse(raw)
	if err != nil || u.Path == "" && u.RawQuery == "" {
		return rec.MatchedParam
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" {
		keys := make([]string, 0, 4)
		for k := range u.Query() {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if len(keys) > 0 {
			path += "?" + strings.Join(keys, "&")
		}
	}
	return path
}

// ingestFindings upserts every finding in findings.jsonl, links it to the
// target and observes it once per scan. Like ingestURLs it returns nothing —
// the scan's findings counter is read back out of scan_observation.
func ingestFindings(ctx context.Context, q *sqlcgen.Queries, scanID, target, artefacts string, hostIDs map[string]int64, now int64, logger *slog.Logger, fails *dbFailures) {
	// seen dedups scan_observation inserts when two artefact lines resolve to the
	// same upserted finding row (UpsertFinding ON CONFLICT) — the same scan must
	// not observe the same asset twice (INTEG-04).
	seen := make(map[int64]struct{})
	forEachJSONL(filepath.Join(artefacts, "findings.jsonl"), logger, func(line []byte) {
		var rec findingRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			return
		}
		// rec.Type is the last fallback so existing signatures are unchanged for
		// records that carry a template id or vuln class. It matters because
		// subdomains.TakeoverRecord emits ONLY {type, host, service, confidence,
		// severity, refs} — no template_id, no vuln_class, no source/category,
		// no matcher_name. Without Type in this chain every real takeover
		// produced sig == "" and was dropped on the floor during ingest, so the
		// store never learned about a class of finding the pipeline had already
		// found, merged and written to disk.
		sig := firstNonEmpty(rec.TemplateID, rec.VulnClass,
			joinNonEmpty("/", rec.Source, rec.Category), rec.MatcherName, rec.Type)
		if sig == "" {
			return // nothing identifiable to key on
		}
		params := sqlcgen.UpsertFindingParams{
			// TargetID is part of ux_findings_dedup (F11). Leaving it empty would
			// put every engagement's findings back into one shared global row,
			// which is the bug plan 15-18 removed.
			TargetID:          target,
			TemplateSignature: sig,
			Tool:              firstNonEmpty(rec.Engine, rec.Service, rec.Type, rec.Source, "reconftw"),
			Severity:          normalizeSeverity(rec.Severity),
			Title:             firstNonEmpty(rec.MatcherName, rec.VulnClass, rec.Category, rec.TemplateID, sig),
			MatchedAt:         firstNonEmpty(rec.MatchedAt, rec.URL, rec.MatchedParam),
			Path:              findingPath(rec),
			Now:               now,
		}
		if id, ok := hostIDs[rec.Host]; ok {
			params.HostID = &id
		}
		row, err := q.UpsertFinding(ctx, params)
		if err != nil {
			logger.DebugContext(ctx, "ingest: upsert finding failed", "sig", sig, "err", err)
			fails.record(fmt.Errorf("upsert finding %q: %w", sig, err))
			return
		}
		if err := q.AttachFindingToTarget(ctx, sqlcgen.AttachFindingToTargetParams{
			TargetID: target, FindingID: row.ID,
		}); err != nil {
			logger.DebugContext(ctx, "ingest: attach finding failed", "sig", sig, "err", err)
			fails.record(fmt.Errorf("attach finding %q: %w", sig, err))
			return
		}
		if _, dup := seen[row.ID]; !dup {
			seen[row.ID] = struct{}{}
			recordObservation(ctx, q, scanID, target, "finding", row.ID, now, logger, fails)
		}
	})
}

// recordObservation writes a scan_observation row linking an asset (host/url/
// finding) to this scan. The cross-cycle diff queries (DiffScansHosts /
// DiffScansURLs / DiffScansFindings) read EXCLUSIVELY from scan_observation, so
// without this the monitor diff is silently empty even against a fully populated
// store (INTEG-04). It is also what the scan's counters are computed from, so a
// rejected insert is recorded as a failure rather than only logged: the row it
// would have counted is not there.
func recordObservation(ctx context.Context, q *sqlcgen.Queries, scanID, target, kind string, assetID, now int64, logger *slog.Logger, fails *dbFailures) {
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
		fails.record(fmt.Errorf("observe %s %d: %w", kind, assetID, err))
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

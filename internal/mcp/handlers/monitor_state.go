// Package handlers — persistent monitor state (F13, acceptance gate 10).
//
// MonitorState is a small SQLite store at <workDir>/monitor/state.db holding the
// three pieces of monitor state that MUST survive a process restart:
//
//  1. generation — a monotonic counter feeding RunOptions.RunGeneration, which
//     is folded into checkpoint.InputHash (common.go). The monitor used to stamp
//     fmt.Sprintf("cycle-%d", loopIndex), which resets to "cycle-0" on every
//     restart: every task's InputHash then matched the first run's, Done()
//     returned true, and the restarted monitor executed NOTHING while logging
//     healthy cycles. A persistent counter is the only fix — an in-memory one
//     cannot see the previous process's values.
//
//  2. baseline_scan_id — the scan the next cycle diffs against. In memory it was
//     lost on restart, so the first cycle after a restart established a fresh
//     baseline and silently skipped an entire delta.
//
//  3. notified fingerprints — the alert-suppression set. In memory it was lost
//     on restart, so a restart re-alerted every finding the operator had already
//     seen (and, combined with defect 6 below, could also lose findings).
//
// Storage shape mirrors internal/core/checkpoint/store.go throughout: the same
// modernc.org/sqlite driver (CGO drivers are forbidden — see that package's doc
// comment), the BYTE-IDENTICAL DSN pragma string, a constructor returning an
// explicit error, and idempotent CREATE TABLE IF NOT EXISTS DDL.
package handlers

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite" // driver registration ("sqlite")
)

// monitorStateDSNPragmas is the DSN query string appended to the state.db path.
//
// It is byte-identical to the one in internal/core/checkpoint/store.go:60 on
// purpose: WAL so a concurrent reader never blocks the monitor's writer,
// busy_timeout(5000) so two monitor processes on one target retry instead of
// failing, and foreign_keys(1) for consistency with the rest of the tree. If
// that constant ever changes, this one changes with it.
const monitorStateDSNPragmas = "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"

// monitorStateDDL creates the two tables and the prune index. Idempotent.
//
// Both tables are keyed by target so one file can serve every target that shares
// a workspace root, and so a fingerprint learned for one target can never
// suppress an alert for another.
const monitorStateDDL = `
CREATE TABLE IF NOT EXISTS monitor_run (
    target           TEXT    NOT NULL PRIMARY KEY,
    generation       INTEGER NOT NULL DEFAULT 0,
    baseline_scan_id TEXT    NOT NULL DEFAULT '',
    updated_at       INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS monitor_notified (
    target      TEXT    NOT NULL,
    fingerprint TEXT    NOT NULL,
    notified_at INTEGER NOT NULL,
    PRIMARY KEY (target, fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_monitor_notified_prune
    ON monitor_notified(target, notified_at);
`

// MonitorState is the SQLite-backed monitor state store. Safe for concurrent
// use: *sql.DB pools connections and every mutation below is a single statement
// inside one transaction, so no read-then-write upgrade can deadlock two
// concurrent writers.
type MonitorState struct {
	db   *sql.DB
	path string
}

// MonitorStateDir returns the directory MonitorState lives in for a workspace.
// Exported so tests (and the dry-run assertions) can name the path that must NOT
// exist without duplicating the join.
func MonitorStateDir(workDir string) string { return filepath.Join(workDir, "monitor") }

// MonitorStatePath returns the state database path for a workspace.
func MonitorStatePath(workDir string) string {
	return filepath.Join(MonitorStateDir(workDir), "state.db")
}

// OpenMonitorState opens (creating if absent) <workDir>/monitor/state.db.
//
// It creates the monitor/ directory: the monitor already writes its incremental
// seed files there, so this adds no new location to the workspace contract.
//
// CALLERS MUST NOT call this on a dry run. A dry run creates no workspace at all
// (F1 / plan 15-05), and a state database is a mutation like any other;
// RunMonitorAsync therefore returns before reaching this function when
// opts.DryRun is set, and TestMonitorDryRunCreatesNoState asserts it.
func OpenMonitorState(workDir string) (*MonitorState, error) {
	if strings.TrimSpace(workDir) == "" {
		return nil, fmt.Errorf("monitor: OpenMonitorState: empty workDir")
	}
	dir := MonitorStateDir(workDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("monitor: mkdir %s: %w", dir, err)
	}
	path := filepath.Join(dir, "state.db")
	db, err := sql.Open("sqlite", path+monitorStateDSNPragmas)
	if err != nil {
		return nil, fmt.Errorf("monitor: open state.db: %w", err)
	}
	// PRAGMA only takes effect on the first real connection; force one now so a
	// broken file fails here rather than mid-cycle.
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("monitor: ping state.db: %w", err)
	}
	if _, err := db.Exec(monitorStateDDL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("monitor: migrations: %w", err)
	}
	return &MonitorState{db: db, path: path}, nil
}

// Path returns the state database path (diagnostics and tests).
func (s *MonitorState) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

// Close releases the underlying handle. Nil-safe and idempotent.
func (s *MonitorState) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// NextGeneration atomically increments and returns the target's generation
// counter. The first call on a fresh database returns 1.
//
// It is ONE statement — an upsert with RETURNING — rather than a SELECT followed
// by an UPDATE. That matters twice over: a read-then-write pair inside a
// deferred-lock transaction is the classic SQLite upgrade deadlock (two readers
// both hold SHARED, both want RESERVED, neither yields), and a read-then-write
// pair without a transaction is a lost-update race that would hand two cycles
// the same generation — which is precisely the replay this store exists to
// prevent. The statement is wrapped in an explicit transaction so the read of
// the RETURNING value and the write are one unit to any concurrent reader.
func (s *MonitorState) NextGeneration(ctx context.Context, target string) (uint64, error) {
	if s == nil || s.db == nil {
		return 0, fmt.Errorf("monitor: NextGeneration: nil state")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("monitor: NextGeneration tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var gen int64
	err = tx.QueryRowContext(ctx, `
		INSERT INTO monitor_run (target, generation, baseline_scan_id, updated_at)
		VALUES (?, 1, '', ?)
		ON CONFLICT(target) DO UPDATE
		    SET generation = monitor_run.generation + 1,
		        updated_at = excluded.updated_at
		RETURNING generation
	`, target, time.Now().UTC().Unix()).Scan(&gen)
	if err != nil {
		return 0, fmt.Errorf("monitor: NextGeneration upsert: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("monitor: NextGeneration commit: %w", err)
	}
	if gen < 0 {
		gen = 0
	}
	return uint64(gen), nil
}

// Generation reports the target's current counter without advancing it.
// Returns 0 when the target has never run.
func (s *MonitorState) Generation(ctx context.Context, target string) (uint64, error) {
	if s == nil || s.db == nil {
		return 0, fmt.Errorf("monitor: Generation: nil state")
	}
	var gen int64
	err := s.db.QueryRowContext(ctx,
		`SELECT generation FROM monitor_run WHERE target = ?`, target).Scan(&gen)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("monitor: Generation query: %w", err)
	}
	if gen < 0 {
		gen = 0
	}
	return uint64(gen), nil
}

// Baseline returns the stored baseline scan id, or "" when none is recorded.
func (s *MonitorState) Baseline(ctx context.Context, target string) (string, error) {
	if s == nil || s.db == nil {
		return "", fmt.Errorf("monitor: Baseline: nil state")
	}
	var id string
	err := s.db.QueryRowContext(ctx,
		`SELECT baseline_scan_id FROM monitor_run WHERE target = ?`, target).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("monitor: Baseline query: %w", err)
	}
	return id, nil
}

// SetBaseline records the scan the NEXT cycle will diff against.
//
// It deliberately does not touch generation: the two advance on different
// schedules (the generation at the START of a cycle, the baseline only after
// that cycle's diff and notifications have completed).
func (s *MonitorState) SetBaseline(ctx context.Context, target, scanID string) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("monitor: SetBaseline: nil state")
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO monitor_run (target, generation, baseline_scan_id, updated_at)
		VALUES (?, 0, ?, ?)
		ON CONFLICT(target) DO UPDATE
		    SET baseline_scan_id = excluded.baseline_scan_id,
		        updated_at       = excluded.updated_at
	`, target, scanID, time.Now().UTC().Unix())
	if err != nil {
		return fmt.Errorf("monitor: SetBaseline upsert: %w", err)
	}
	return nil
}

// WasNotified reports whether fingerprint has already been dispatched for target.
func (s *MonitorState) WasNotified(ctx context.Context, target, fingerprint string) (bool, error) {
	if s == nil || s.db == nil {
		return false, fmt.Errorf("monitor: WasNotified: nil state")
	}
	var one int
	err := s.db.QueryRowContext(ctx,
		`SELECT 1 FROM monitor_notified WHERE target = ? AND fingerprint = ?`,
		target, fingerprint).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("monitor: WasNotified query: %w", err)
	}
	return true, nil
}

// MarkNotified records fingerprint as dispatched.
//
// CALL ORDER IS LOAD-BEARING: the monitor calls this only AFTER a notification
// has actually succeeded. Marking first (the previous behaviour) meant a
// transient Slack outage permanently suppressed a critical finding — the retry
// never happened because the fingerprint was already in the set.
func (s *MonitorState) MarkNotified(ctx context.Context, target, fingerprint string) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("monitor: MarkNotified: nil state")
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO monitor_notified (target, fingerprint, notified_at)
		VALUES (?, ?, ?)
		ON CONFLICT(target, fingerprint) DO UPDATE
		    SET notified_at = excluded.notified_at
	`, target, fingerprint, time.Now().UTC().Unix())
	if err != nil {
		return fmt.Errorf("monitor: MarkNotified upsert: %w", err)
	}
	return nil
}

// PruneNotified deletes suppression entries last notified before olderThan.
//
// Without it the table grows without bound on a monitor that runs for months —
// the same unbounded-growth failure the in-memory map had, only durable.
func (s *MonitorState) PruneNotified(ctx context.Context, target string, olderThan time.Time) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("monitor: PruneNotified: nil state")
	}
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM monitor_notified WHERE target = ? AND notified_at < ?`,
		target, olderThan.UTC().Unix())
	if err != nil {
		return fmt.Errorf("monitor: PruneNotified delete: %w", err)
	}
	return nil
}

// CountNotified returns how many fingerprints are suppressed for target.
// Diagnostics and tests only.
func (s *MonitorState) CountNotified(ctx context.Context, target string) (int, error) {
	if s == nil || s.db == nil {
		return 0, fmt.Errorf("monitor: CountNotified: nil state")
	}
	var n int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM monitor_notified WHERE target = ?`, target).Scan(&n); err != nil {
		return 0, fmt.Errorf("monitor: CountNotified query: %w", err)
	}
	return n, nil
}

// ---------------------------------------------------------------------------
// Finding fingerprints
// ---------------------------------------------------------------------------

// findingFingerprint returns a stable 32-hex-char identity for one finding
// INSTANCE, used as the alert-suppression key.
//
// It replaces findingContentHash(templateSig, severity, matchedAt), which folded
// in only three inputs and — because the monitor passed the finding TITLE as
// matchedAt — collapsed every instance of one template at one severity into a
// single fingerprint. The same misconfiguration on fifty hosts alerted once and
// the other forty-nine were suppressed forever. Host and path are therefore part
// of the identity.
//
// The locator is normalised with the same concept as ingest.findingPath: scheme,
// host, fragment and query VALUES are dropped, query KEYS are kept and sorted.
// That keeps ?id= and ?user= on one path distinct (genuinely different findings)
// without carrying payloads or secrets into the database (XCUT-07).
//
// The width is unchanged (32 hex chars, a SHA-256 prefix), but the INPUT changed,
// so fingerprints stored by an older build will not match. That direction is
// safe: an unmatched fingerprint causes a one-time re-notification, never a
// suppression of something unseen.
func findingFingerprint(templateSig, severity, host, locator string) string {
	h := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(templateSig)) + "|" +
		strings.ToLower(strings.TrimSpace(severity)) + "|" +
		strings.ToLower(strings.TrimSpace(host)) + "|" +
		normalizeFindingLocator(locator)))
	return hex.EncodeToString(h[:16]) // 32 hex chars
}

// normalizeFindingLocator reduces a finding locator to its path + sorted query
// keys. Mirrors internal/core/ingest.findingPath; a bare, unparseable or
// path-less locator degrades to the trimmed input so two different bare
// locators still differ.
func normalizeFindingLocator(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Path == "" && u.RawQuery == "") {
		return strings.ToLower(raw)
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

// findingHostFromLocator extracts the hostname from a finding locator. Returns
// "" when the locator carries no host (a bare path, or a bare hostname that
// url.Parse reports as a path — the exact shape that made plan 15-14's F19 fix
// inert, so it is handled explicitly here).
func findingHostFromLocator(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
		return strings.ToLower(u.Hostname())
	}
	// No scheme: url.Parse puts "host/path" entirely in Path. Take the first
	// segment when it looks like a hostname rather than a path.
	if strings.HasPrefix(raw, "/") {
		return ""
	}
	seg := raw
	if i := strings.IndexAny(seg, "/?#"); i >= 0 {
		seg = seg[:i]
	}
	if seg == "" || !strings.Contains(seg, ".") {
		return ""
	}
	if i := strings.LastIndex(seg, ":"); i > 0 {
		seg = seg[:i]
	}
	return strings.ToLower(seg)
}

// firstNonEmptyString returns the first argument that is not blank.
func firstNonEmptyString(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

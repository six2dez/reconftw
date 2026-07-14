-- schema.sql — hand-authored DDL for the reconFTW v2 data store (store.db).
--
-- WHY THIS FILE EXISTS: the sqlc query layer (*.sql.go) was generated from .sql
-- sources that were never checked in (no sqlc.yaml / sqlc binary in-repo), so the
-- production runtime had no way to CREATE the tables the queries target. This DDL
-- is the authoritative schema, kept column-for-column in sync with models.go and
-- the INSERT/UPSERT column lists + ON CONFLICT keys in the generated queries.
--
-- All statements are IF NOT EXISTS / idempotent so EnsureSchema can run on every
-- open. FTS5 virtual tables (findings_ft, urls_ft) and their sync triggers are
-- intentionally omitted — the full-text search endpoint is out of scope for the
-- Wave-0 store bring-up and its absence does not affect any INSERT (no triggers
-- reference the missing tables).

CREATE TABLE IF NOT EXISTS companies (
    id          TEXT PRIMARY KEY,
    name        TEXT    NOT NULL,
    description TEXT    NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS targets (
    id          TEXT PRIMARY KEY,
    name        TEXT    NOT NULL DEFAULT '',
    description TEXT    NOT NULL DEFAULT '',
    company_id  TEXT,
    recon_dir   TEXT    NOT NULL DEFAULT '',
    tags_json   TEXT    NOT NULL DEFAULT '[]',
    notes       TEXT    NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS target_roots (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id  TEXT    NOT NULL,
    root_value TEXT    NOT NULL,
    root_type  TEXT    NOT NULL,
    scope_kind TEXT    NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id                    TEXT PRIMARY KEY,
    target_id             TEXT    NOT NULL,
    mode                  TEXT    NOT NULL,
    status                TEXT    NOT NULL,
    started_at            INTEGER NOT NULL,
    finished_at           INTEGER,
    exit_code             INTEGER,
    reconftw_version      TEXT,
    tool_versions_json    TEXT,
    raw_args_json         TEXT    NOT NULL DEFAULT '{}',
    config_overrides_json TEXT    NOT NULL DEFAULT '{}',
    output_dir            TEXT    NOT NULL DEFAULT '',
    cancelled_by          TEXT,
    findings_count        INTEGER NOT NULL DEFAULT 0,
    subdomain_count       INTEGER NOT NULL DEFAULT 0,
    url_count             INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_scans_target_started ON scans(target_id, started_at DESC);

CREATE TABLE IF NOT EXISTS hosts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    fqdn          TEXT    NOT NULL UNIQUE,
    ip_current    TEXT,
    asn           INTEGER,
    asn_org       TEXT,
    cdn           TEXT,
    first_seen_at INTEGER NOT NULL,
    last_seen_at  INTEGER NOT NULL,
    status        TEXT    NOT NULL DEFAULT 'new',
    tags_json     TEXT    NOT NULL DEFAULT '[]',
    notes         TEXT    NOT NULL DEFAULT '',
    raw_json      TEXT
);

CREATE TABLE IF NOT EXISTS target_host (
    target_id TEXT    NOT NULL,
    host_id   INTEGER NOT NULL,
    PRIMARY KEY (target_id, host_id)
);

CREATE TABLE IF NOT EXISTS ports (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id         INTEGER NOT NULL,
    port_number     INTEGER NOT NULL,
    protocol        TEXT    NOT NULL,
    state           TEXT    NOT NULL,
    service_name    TEXT,
    service_version TEXT,
    banner          TEXT,
    first_seen_at   INTEGER NOT NULL,
    last_seen_at    INTEGER NOT NULL,
    tags_json       TEXT    NOT NULL DEFAULT '[]',
    raw_json        TEXT,
    UNIQUE (host_id, port_number, protocol)
);

CREATE TABLE IF NOT EXISTS target_port (
    target_id TEXT    NOT NULL,
    port_id   INTEGER NOT NULL,
    PRIMARY KEY (target_id, port_id)
);

CREATE TABLE IF NOT EXISTS urls (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    url             TEXT    NOT NULL,
    url_hash        BLOB    NOT NULL UNIQUE,
    scheme          TEXT    NOT NULL,
    host_id         INTEGER,
    port            INTEGER,
    path            TEXT    NOT NULL DEFAULT '',
    query_canonical TEXT    NOT NULL DEFAULT '',
    status_code     INTEGER,
    content_type    TEXT,
    content_length  INTEGER,
    title           TEXT,
    tech_json       TEXT,
    screenshot_path TEXT,
    first_seen_at   INTEGER NOT NULL,
    last_seen_at    INTEGER NOT NULL,
    status          TEXT    NOT NULL DEFAULT 'new',
    tags_json       TEXT    NOT NULL DEFAULT '[]',
    notes           TEXT    NOT NULL DEFAULT '',
    raw_json        TEXT
);

CREATE TABLE IF NOT EXISTS target_url (
    target_id TEXT    NOT NULL,
    url_id    INTEGER NOT NULL,
    PRIMARY KEY (target_id, url_id)
);

CREATE TABLE IF NOT EXISTS findings (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    template_signature TEXT    NOT NULL,
    tool               TEXT    NOT NULL,
    host_id            INTEGER,
    port_id            INTEGER,
    url_id             INTEGER,
    path               TEXT    NOT NULL DEFAULT '',
    severity           TEXT    NOT NULL,
    status             TEXT    NOT NULL DEFAULT 'open',
    title              TEXT    NOT NULL DEFAULT '',
    description        TEXT    NOT NULL DEFAULT '',
    evidence           TEXT    NOT NULL DEFAULT '',
    matched_at         TEXT    NOT NULL DEFAULT '',
    cvss_score         REAL,
    tags_json          TEXT    NOT NULL DEFAULT '[]',
    notes              TEXT    NOT NULL DEFAULT '',
    raw_json           TEXT,
    first_seen_at      INTEGER NOT NULL,
    last_seen_at       INTEGER NOT NULL
);
-- Matches the UpsertFinding ON CONFLICT target exactly (expression index).
CREATE UNIQUE INDEX IF NOT EXISTS ux_findings_dedup
    ON findings(template_signature, tool, COALESCE(host_id, 0), COALESCE(port_id, 0), path);

CREATE TABLE IF NOT EXISTS target_finding (
    target_id  TEXT    NOT NULL,
    finding_id INTEGER NOT NULL,
    PRIMARY KEY (target_id, finding_id)
);

CREATE TABLE IF NOT EXISTS js_files (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256        BLOB    NOT NULL,
    size_bytes    INTEGER NOT NULL,
    host_id       INTEGER,
    source_url_id INTEGER,
    storage_path  TEXT,
    secrets_count INTEGER NOT NULL DEFAULT 0,
    first_seen_at INTEGER NOT NULL,
    last_seen_at  INTEGER NOT NULL,
    tags_json     TEXT    NOT NULL DEFAULT '[]',
    notes         TEXT    NOT NULL DEFAULT '',
    raw_json      TEXT,
    UNIQUE (sha256)
);

CREATE TABLE IF NOT EXISTS target_j (
    target_id TEXT    NOT NULL,
    js_id     INTEGER NOT NULL,
    PRIMARY KEY (target_id, js_id)
);

CREATE TABLE IF NOT EXISTS settings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scope           TEXT    NOT NULL,
    target_id       TEXT,
    key             TEXT    NOT NULL,
    value_plain     TEXT,
    value_encrypted BLOB,
    is_secret       INTEGER NOT NULL DEFAULT 0,
    last_test_at    INTEGER,
    last_test_ok    INTEGER,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_observation (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     TEXT    NOT NULL,
    target_id   TEXT    NOT NULL,
    asset_kind  TEXT    NOT NULL,
    asset_id    INTEGER NOT NULL,
    observed_at INTEGER NOT NULL,
    raw_json    TEXT
);

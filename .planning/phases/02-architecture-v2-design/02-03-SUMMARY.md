---
phase: 02-architecture-v2-design
plan: "03"
subsystem: planning/adr
tags: [architecture, output-tree, compat-layer, adr, jsonl, sqlite, atomic-write, symlink]

dependency_graph:
  requires:
    - "02-01"
    - "02-02"
  provides:
    - "§3 Output Tree Layout in ADR 0002 (ARCH-03 satisfied)"
    - "§4 Compat Symlink Layer in ADR 0002 (ARCH-04 satisfied)"
  affects:
    - "Phase 3 Foundation Kernel (reads §3 for workspace init, checkpoints.db, AtomicWriter)"
    - "Phase 4-7 Module ports (read §3 for OutputTree.Append contract)"
    - "Phase 11 Installer/migrator (reads §4 for compat writer implementation)"
    - "Phase 12 Cutover (reads §4 for 6-month timeline and CUT-08)"

tech_stack:
  added: []
  patterns:
    - "AtomicWriter 4-step: tempfile (same dir) + fsync + rename(2) + parent-dir fsync"
    - "AtomicSymlink: CreateTemp name-slot + os.Symlink + os.Rename (atomic POSIX)"
    - "SQLite WAL mode for checkpoints.db with (task_name, target, input_hash) PK"
    - "JSONL artefact files with deduplication and OutOfScope guard at OutputTree.Append boundary"
    - "LifecycleAware.OnEnd() hook for compat writer"

key_files:
  created: []
  modified:
    - path: ".planning/decisions/0002-architecture-v2.md"
      description: "§3 Output Tree Layout and §4 Compat Symlink Layer — both stubs replaced with full content"

decisions:
  - "workspaces/<target-id>/ tree with _compat/ subdirectory for v1 path compatibility"
  - "checkpoints.db idempotency key is (task_name, target, input_hash) — content-addressed, not touch-file"
  - "state.db separated from checkpoints.db to allow independent clearing per mode"
  - "AtomicWriter is the only write path for artefacts/ — no direct os.WriteFile permitted"
  - "Compat layer maintained for 6 months post v2.0 GA cutover per CUT-08"
  - "Representative 7-row v1→v2 mapping table unblocks Phase 3-4; full 40+ mapping in Phase 11"
  - "CompatWriter errors are WARN-only — never fail the parent task"

metrics:
  duration: "~20 minutes"
  completed: "2026-05-28"
  tasks_completed: 2
  tasks_total: 2
  files_modified: 1
---

# Phase 02 Plan 03: Output Tree Layout and Compat Symlink Layer Summary

Populated §3 Output Tree Layout and §4 Compat Symlink Layer in ADR 0002 with the full
workspaces/<target-id>/ directory tree, JSONL artefact schemas, checkpoints.db SQLite schema,
AtomicWriter 4-step contract, AtomicSymlink Go snippet, representative 7-row v1→v2 mapping
table, and the 6-month compat lifecycle timeline.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Write §3 Output Tree Layout | dcdcc4b8 | `.planning/decisions/0002-architecture-v2.md` |
| 2 | Write §4 Compat Symlink Layer | dcdcc4b8 | `.planning/decisions/0002-architecture-v2.md` |

(Tasks 1 and 2 were committed atomically in a single commit since they modify the same file
and Task 2 was written after Task 1 in sequence with no intervening verification gate.)

## What Was Built

### §3 Output Tree Layout (ARCH-03)

**§3.1 Directory Structure** — full ASCII tree for `workspaces/<target-id>/` including:
- `manifest.json`, `checkpoints.db`, `state.db` at workspace root
- `inputs/` with `config.snapshot.toml` (secrets redacted) and `wordlists.lock`
- `artefacts/` with 5 JSONL files: subdomains, hosts, urls, findings, notes
- `raw/<toolname>/` for per-tool forensic stdout
- `reports/` with HTML, SARIF 2.1.0, and JSON formats
- `logs/` with structured run log and debug log
- `_compat/` as the compat writer output directory

**§3.2 Artefact JSONL Schemas** — per-file schemas for all 5 artefact types. Includes
deduplication key per file and the OutOfScope guard at `OutputTree.Append()` boundary
(closes threat T-02-03-02).

**§3.3 manifest.json Schema** — 7 fields: `workspace_version`, `target`, `target_id`,
`started_at`, `finished_at`, `tool_versions`, `config_hash`.

**§3.4 checkpoints.db Schema** — SQLite `tasks` table with composite PK
`(task_name, target, input_hash)`. Full idempotency rule: `status=done` → skip;
`status=errored|cancelled` → re-run. Input hash is content-addressed (SHA-256 of
config slice + wordlists.lock) — replaces v1's bash `touch` sentinel files.

**§3.5 AtomicWriter Contract** — 4-step pattern cited to canonical implementation at
`spike/go/internal/output/atomic.go`. Step 4 (parent-dir fsync) explicitly called out as
"the often-missed critical step." AtomicWriter is the ONLY write path for artefacts/.

### §4 Compat Symlink Layer (ARCH-04)

**§4.1 AtomicSymlink Pattern** — complete Go snippet from RESEARCH.md. Note on macOS APFS
atomic rename(2) support.

**§4.2 Compat Directory Structure** — `_compat/` subdirectory ASCII tree. Top-level
`Recon/<domain>` symlink points to `workspaces/<target-id>/_compat/` via WorkspaceInit().

**§4.3 Representative V1→V2 Mapping Table** — 7-row table covering:
subdomains.txt, subdomains_alive.txt, webs.txt, vulns/, nuclei_output/, screenshots/, osint/.
Phase 11 will implement the full 40+ file mapping.

**§4.4 Compat Writer Lifecycle** — `LifecycleAware.OnEnd()` hook fires after each successful
task. Compat failures are WARN-only (never fail the task). Init-time symlink is idempotent.

**§4.5 Timeline** — 6-month post-GA maintenance window per CUT-08. Migration target paths
documented for downstream script authors.

## Deviations from Plan

None — plan executed exactly as written. Both §3 and §4 were written sequentially as
specified. The single-commit approach for both tasks (they modify the same file) was used
to maintain a clean git history without a trivial intermediate state.

## Threat Surface Scan

No new network endpoints, auth paths, file access patterns, or schema changes at trust
boundaries were introduced. This is a documentation-only plan.

## Known Stubs

None — §3 and §4 are fully populated. The ADR still has stubs in §1, §5-§12 which are
out of scope for this plan (populated in other Wave 2 plans).

## Self-Check

**Files committed:**

- `.planning/decisions/0002-architecture-v2.md` in commit `dcdcc4b8` on branch
  `worktree-agent-aaff4762defe6522a`

**Grep verification (run against committed file):**

```
grep '## §3 Output Tree'   → 1 match  PASS
grep 'workspaces/'         → 6+ refs  PASS
grep 'input_hash'          → 4 refs   PASS
grep 'AtomicWriter'        → 8 refs   PASS
grep 'manifest.json'       → 3 refs   PASS
grep -c 'jsonl'            → 22 refs  PASS (≥5 required)
grep 'ARCH-03'             → 3 refs   PASS
grep '## §4 Compat'        → 1 match  PASS
grep 'AtomicSymlink'       → 6 refs   PASS
grep 'Recon/'              → 20 refs  PASS (≥4 required)
grep '_compat/'            → 13 refs  PASS
grep '6 months'            → 4 refs   PASS
grep 'ARCH-04'             → 3 refs   PASS
grep 'LifecycleAware'      → 1 ref    PASS
No [STUB in §3 body        → PASS
No [STUB in §4 body        → PASS
§2 HTTPX_RATELIMIT count   → 7 refs   PASS (unchanged)
```

## Self-Check: PASSED

---
phase: 05-web-pipeline-e2e
plan: "05"
subsystem: web
tags: [bypass, iis-shortname, xss-reflection, param-discovery, repo-clone, deep-only]
dependency_graph:
  requires:
    - 05-02  # ffuf (fuzz.jsonl), nuclei (findings.jsonl)
    - 05-04  # urldedup (urls.jsonl)
  provides:
    - nomore403 bypass findings → artefacts/findings.jsonl
    - IIS shortname findings → artefacts/findings.jsonl
    - XSS reflection findings → artefacts/findings.jsonl
    - Parameter discovery findings → artefacts/findings.jsonl
  affects:
    - findings.jsonl (extended with bypass/iis/xss/param records)
tech_stack:
  added:
    - os/exec direct invocation (nomore403 repo-clone with cmd.Dir + stdin)
    - Gxss stdin pipeline with inline Go FUZZ replacement (no shell interpolation)
  patterns:
    - Repo-clone binary: os.Stat + absolute path + cmd.Dir (T-05-16 / Pitfall 2)
    - Deep-mode gate: cfg.Advanced.Deep check before arjun run
    - Backend.Stream mandatory for arjun (XCUT-09 / Pitfall 5, 2h timeout)
key_files:
  created:
    - internal/modules/web/nomore403.go
    - internal/modules/web/shortscan.go
    - internal/modules/web/gxss.go
    - internal/modules/web/arjun.go
  modified: []
decisions:
  - "Nomore403Task uses os.Stat (not exec.LookPath) for repo-clone binary detection, matching v1 pattern; cmd.Dir set to toolsDir/nomore403 per Pitfall 2 mitigation (T-05-16)"
  - "GxssTask implements qsreplace FUZZ inline via url.Parse/url.Values — no shell interpolation (T-05-17); qsreplace binary is not a hard dependency"
  - "ArjunTask defaults to deep_only=true via cfg.Advanced.Deep gate, matching v1 web.sh:1289 DEEP mode restriction (Open Question 1 RESOLVED)"
  - "Nomore403Task uses Vulns.Bypass4xx.Enabled (not a Web-subtree flag) since the bypass behavior maps to the vulns config section where it is defined in v1"
metrics:
  duration_minutes: 25
  completed: "2026-06-02"
  tasks_completed: 2
  tasks_total: 2
  files_created: 4
  files_modified: 0
---

# Phase 05 Plan 05: Group-C Bypass + Group-D Param Discovery Summary

**One-liner:** 4xx bypass via nomore403 (repo-clone, CWD-aware), IIS shortname via shortscan, XSS reflection via Gxss (inline FUZZ replacement), parameter discovery via arjun (deep-only + Backend.Stream heartbeat).

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Group-C bypass pipeline (Nomore403Task + ShortscanTask) | 2e4de6ac | nomore403.go, shortscan.go |
| 2 | Group-D param discovery (GxssTask + ArjunTask) | 368768a9 | gxss.go, arjun.go |

## Implementation Notes

### Nomore403Task (nomore403.go)

- `Name()` = `"web.nomore403"`, `DependsOn()` = `["web.ffuf"]`
- Binary check: `os.Stat(toolsDir/nomore403/nomore403)` — NOT `exec.LookPath` (repo-clone)
- `cmd.Dir = toolsDir/nomore403` — critical Pitfall 2 mitigation (nomore403 has relative wordlist paths)
- Reads `artefacts/fuzz.jsonl`; filters status 400-499 excluding 404
- Writes `FindingRecord{TemplateID: "nomore403-bypass", Severity: "medium", Type: "http"}`
- `Enabled()` maps to `cfg.Vulns.Bypass4xx.Enabled`

### ShortscanTask (shortscan.go)

- `Name()` = `"web.shortscan"`, `DependsOn()` = `["web.nuclei"]`
- Binary check: `exec.LookPath("shortscan")`
- Reads `artefacts/findings.jsonl`; filters `template_id == "iis-version"`
- Arg vector: `shortscan <url> -F -s -p 1` (verbatim v1 form, web.sh:1610)
- Output filter: only records output containing `"Vulnerable: Yes"` (v1 filter)
- Writes `FindingRecord{TemplateID: "shortscan", Type: "iis-shortname"}`

### GxssTask (gxss.go)

- `Name()` = `"web.gxss"`, `DependsOn()` = `["web.urldedup"]`
- Binary check: `exec.LookPath("Gxss")`
- Reads `artefacts/urls.jsonl`; filters URLs containing `"?"`
- FUZZ replacement: inline Go via `url.Parse` + `url.Values` — no `qsreplace` shell dependency (T-05-17)
- Arg vector: `Gxss -c 100 -p Xss` via stdin (verbatim v1 form, vulns.sh:27)
- Writes `FindingRecord{TemplateID: "gxss-reflection", Severity: "medium", Type: "xss"}`

### ArjunTask (arjun.go)

- `Name()` = `"web.arjun"`, `DependsOn()` = `["web.urldedup"]`
- Deep-mode gate: skips unless `cfg.Advanced.Deep == true` (v1 web.sh:1289 behavior, Open Q1 resolved)
- Reads `artefacts/urls.jsonl`; threads from `cfg.Advanced.Tools.Arjun.Threads` (default 10, fallback `NCPU*5`)
- Arg vector: `arjun -i <file> -t <threads> -oT <staging>` (verbatim v1, web.sh:1329)
- Uses `app.Tools.Stream` (Backend.Stream) — MANDATORY for XCUT-09 / Pitfall 5 (2h timeout)
- Writes `FindingRecord{TemplateID: "arjun-param", Severity: "info", Type: "parameter"}`

## Deviations from Plan

### Auto-fixed Issues

None — plan executed exactly as written.

### Minor Adaptations

**1. [Rule 2 - Config alignment] Nomore403Task.Enabled uses cfg.Vulns.Bypass4xx.Enabled**
- **Found during:** Task 1 — `cfg.Web.BypassEnabled` does not exist in WebConfig
- **Fix:** Mapped to `cfg.Vulns.Bypass4xx.Enabled` which is the config field where nomore403 bypass is defined in the existing config schema (defaults to `true`, matching v1 behavior)
- **Impact:** Semantically equivalent; Bypass4xx is in the Vulns config section consistent with where nomore403 lives in v1 (vulns.sh)

**2. [Rule 2 - Config alignment] ArjunTask deep_only uses cfg.Advanced.Deep**
- **Found during:** Task 2 — `WebParamDiscover` struct only has `Enabled bool`; no `DeepOnly` field exists
- **Fix:** Used `cfg.Advanced.Deep` as the deep mode gate, matching v1's `if [[ $DEEP != true ]]; then skip_notification "mode"` at web.sh:1289
- **Impact:** Correct behavior; deep mode is a global advanced setting, not per-tool

## Security Mitigations Applied (per threat_model)

| Threat ID | Mitigation Applied |
|-----------|-------------------|
| T-05-16 | nomore403 cmd.Dir = toolsDir/nomore403; binary invoked as absolute path |
| T-05-17 | FUZZ replacement inline in Go (url.Parse + url.Values); no shell interpolation |
| T-05-18 | ArjunTask uses Backend.Stream (app.Tools.Stream) with XCUT-09 heartbeat |
| T-05-19 | Gxss/nomore403 stdout routed to outBuf only; not logged at INFO terminal level |
| T-05-SC | Gxss binary resolved via exec.LookPath; path not user-controlled |

## Known Stubs

None — all four tasks implement real logic reading from actual artefact files.

## Threat Flags

None — no new network endpoints, auth paths, or trust boundaries introduced. All new surface is outbound tool invocation, consistent with the existing web pipeline pattern.

## Self-Check

- [x] internal/modules/web/nomore403.go exists and compiles
- [x] internal/modules/web/shortscan.go exists and compiles
- [x] internal/modules/web/gxss.go exists and compiles
- [x] internal/modules/web/arjun.go exists and compiles
- [x] Commit 2e4de6ac exists (Task 1: nomore403 + shortscan)
- [x] Commit 368768a9 exists (Task 2: gxss + arjun)
- [x] go build ./... exits 0
- [x] go test ./... exits 0

## Self-Check: PASSED

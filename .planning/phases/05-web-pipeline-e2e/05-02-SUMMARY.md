---
phase: 05-web-pipeline-e2e
plan: "02"
subsystem: web-pipeline
tags: [nuclei, ffuf, screenshots, findings-jsonl, fuzz-jsonl, backend-stream, xcut-09, sha256, content-addressed]

# Dependency graph
requires:
  - phase: 05-01
    provides: web package scaffold (doc.go, httpx.go, merge.go), hosts.jsonl artefact schema, HTTPXTask DAG root
  - phase: 04-subdomains-e2e-axiom-integration
    provides: findings.jsonl SARIF-compatible schema (Phase 4 TakeoverRecord shape), Backend.Stream pattern, task.Register, AppContext

provides:
  - NucleiTask: nuclei templated scanner with WAF rate-halving, Backend.Stream, findings.jsonl SARIF output
  - ScreenshotTask: nuclei-headless screenshots with SHA-256 content-addressed PNG rename
  - FfufTask: web directory/file fuzzer with Backend.Stream, FFUF_THREADS_MAX cap, fuzz.jsonl output
affects:
  - 05-03 (infra tools depend on web.httpx root; nuclei/ffuf outputs feed downstream)
  - 06-vulns (findings.jsonl feeds vuln pipeline; fuzz.jsonl feeds nomore403)
  - 10-monitor (findings.jsonl SARIF, raw/screenshots/<hash>.png content-addressed blobs)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Backend.Stream heartbeat for long-running tools (nuclei, ffuf) per XCUT-09 (Pitfall 5)"
    - "WAF rate-halving: waf.jsonl set lookup → rl/3 for WAF hosts (v1 web.sh:1121 behavior)"
    - "D-W6 best_effort fail-soft: exec.LookPath + os.Stat checks → StatusSkipped, never StatusFail"
    - "D-W5 content-addressed rename: filepath.Walk → sha256.Sum256 → raw/screenshots/<hex>.png"
    - "T-05-05 URL scheme validation (http/https) before ffuf -u arg construction"
    - "T-05-06 thread cap: min(cfg.Web.Fuzz.Threads, cfg.Advanced.Tools.FFUF.Threads)"
    - "JSONL fallback parser: try JSON object first, then per-line JSONL (ffuf output)"

key-files:
  created:
    - internal/modules/web/nuclei.go
    - internal/modules/web/screenshot.go
    - internal/modules/web/ffuf.go
  modified: []

key-decisions:
  - "NucleiTask DependsOn [web.httpx, web.wafw00f] to ensure waf.jsonl exists for WAF rate-halving; best_effort means absent waf.jsonl falls back to running all hosts at normal rate"
  - "ScreenshotTask returns StatusSkipped (not StatusFail) on missing nuclei binary, missing templates, or 0 PNGs produced — never blocks pipeline (D-W6)"
  - "FfufTask uses cfg.Advanced.Tools.FFUF.Threads as FFUF_THREADS_MAX cap, not a separate field — matching existing config schema"
  - "ffuf URL validation rejects non-http/https schemes before -u flag construction (T-05-05 scope filter)"
  - "Both nuclei and screenshot Tasks use app.Tools.Stream (Runner.Stream) which resolves through ToolRegistry, not direct Backend.Stream"

patterns-established:
  - "readHostURLsFromJSONL: shared helper (nuclei.go) reads artefacts/hosts.jsonl url/host fields — reused by screenshot.go indirectly via its own readScreenshotHosts"
  - "WAF set construction from waf.jsonl: readWAFHostsSet returns empty map on missing file (step-b fallback pattern)"
  - "resolveFFUFThreads: dedicated helper isolates FFUF_THREADS_MAX cap logic"
  - "validateFFUFURL: url.Parse + scheme check before interpolating into tool args"

requirements-completed:
  - WEB-02
  - WEB-03
  - WEB-06

# Metrics
duration: 35min
completed: 2026-06-02
---

# Phase 5 Plan 02: NucleiTask + ScreenshotTask + FfufTask Summary

**nuclei templated scanner (findings.jsonl SARIF), nuclei-headless screenshots (SHA-256 content-addressed PNGs), and ffuf directory fuzzer (fuzz.jsonl) with Backend.Stream heartbeats and WAF rate-halving**

## Performance

- **Duration:** ~35 min (continuation from interrupted prior run)
- **Started:** 2026-06-02T14:30:00Z
- **Completed:** 2026-06-02T15:05:00Z
- **Tasks:** 2 (Task 1 pre-written by prior run; committed + Task 2 implemented)
- **Files created:** 3

## Accomplishments

- NucleiTask: runs nuclei with WAF rate-halving (rl/3 for WAF hosts from waf.jsonl), Backend.Stream for XCUT-09, writes SARIF-compatible FindingRecord to artefacts/findings.jsonl
- ScreenshotTask: nuclei-headless with explicit StatusSkipped on missing nuclei binary or templates (D-W6), content-addressed PNG rename to raw/screenshots/<sha256hex>.png (D-W5)
- FfufTask: per-host ffuf with Backend.Stream (Pitfall 5), FFUF_THREADS_MAX cap (T-05-06), http/https URL scheme validation (T-05-05), fuzz.jsonl D-W11 schema

## Task Commits

1. **Task 1: NucleiTask + ScreenshotTask** - `b0687ce8` (feat)
2. **Task 2: FfufTask** - `878659c8` (feat)

**Plan metadata:** (tracked below in final commit)

## Files Created/Modified

- `internal/modules/web/nuclei.go` — NucleiTask: nuclei scanner, WAF rate-halving, Backend.Stream, findings.jsonl writer; init() registers with task.Register
- `internal/modules/web/screenshot.go` — ScreenshotTask: nuclei-headless, D-W6 skip guards, SHA-256 content-addressed PNG rename; init() registers
- `internal/modules/web/ffuf.go` — FfufTask: ffuf per-host fuzzer, Backend.Stream, FFUF_THREADS_MAX cap, URL scheme validation, fuzz.jsonl writer; init() registers

## Decisions Made

- NucleiTask DependsOn includes "web.wafw00f" (not just "web.httpx") so waf.jsonl is present for WAF rate-halving, matching v1 web.sh:969→1149 sequencing; best_effort means a missing waf.jsonl falls back to all-hosts at normal rate.
- FfufTask uses `cfg.Advanced.Tools.FFUF.Threads` as the ThreadsMax cap (existing config field FFUF_THREADS_MAX maps here via legacy alias), rather than a dedicated `cfg.Web.Fuzz.ThreadsMax` field that doesn't exist in the current config schema.
- Both nuclei and ffuf use `app.Tools.Stream` (Runner.Stream → registry lookup → Backend.Stream) per the Runner abstraction; Tasks never call Backend directly.

## Deviations from Plan

None — plan executed exactly as written. The prior executor had written Task 1 correctly; Task 2 (ffuf.go) implemented from scratch following plan spec.

## Issues Encountered

None — prior run had left nuclei.go and screenshot.go in a valid state. Build succeeded on first attempt for both tasks.

## Threat Flags

All T-05-04, T-05-05, T-05-06 mitigations implemented as planned:
- T-05-04: nuclei stdout routed to run.log via app.Tools.Stream drain; not logged at INFO
- T-05-05: validateFFUFURL checks http/https scheme + non-empty host before -u flag construction
- T-05-06: resolveFFUFThreads caps at min(computed, cfg.Advanced.Tools.FFUF.Threads)

No new threat surface introduced beyond what the plan's threat model covers.

## Known Stubs

None — all three tasks wire real data sources (artefacts/hosts.jsonl, artefacts/waf.jsonl) and real tool invocations. No placeholder data flows to UI.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- Plan 03 (infra tools: wafw00f, cdncheck, hakoriginfinder, csprecon, favirecon, VhostFinder) can proceed
- web.nuclei, web.screenshot, web.ffuf are registered in the task.Default registry
- findings.jsonl SARIF schema established for Phase 6 (Vulns) and Phase 10 (Monitor/Reporting)
- fuzz.jsonl established for nomore403 (WEB-12, Plan 05 bypass tools)

## Self-Check: PASSED

- nuclei.go: FOUND
- screenshot.go: FOUND
- ffuf.go: FOUND
- 05-02-SUMMARY.md: FOUND
- Commit b0687ce8: FOUND (Task 1 — NucleiTask + ScreenshotTask)
- Commit 878659c8: FOUND (Task 2 — FfufTask)

---
*Phase: 05-web-pipeline-e2e*
*Completed: 2026-06-02*

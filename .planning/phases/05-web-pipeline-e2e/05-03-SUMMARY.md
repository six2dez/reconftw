---
phase: 05-web-pipeline-e2e
plan: "03"
subsystem: web-pipeline
tags: [web, waf, cdn, csp, favicon, vhost, extractor, infra]
dependency_graph:
  requires: [05-01, 05-02]
  provides: [web.wafw00f, web.cdncheck, web.hakoriginfinder, web.csprecon, web.favirecon, web.vhostfinder, extract/waf, extract/csp, extract/favicon/web]
  affects: [web.nuclei]
tech_stack:
  added:
    - internal/extract/waf (pure-transform WAF/CDN result parsers)
    - internal/extract/csp (pure-transform CSP hostname extractor)
    - internal/extract/favicon/web.go (JSON favicon extractor extension)
  patterns:
    - pure-transform extractor (D-W3): Extract(rawOutput, domain) → []Result
    - best_effort Task with StatusSkipped on binary absent
    - IP extraction before cdncheck (Pitfall 8 mitigation)
    - case-insensitive JSON field access for favirecon (Open Question 4)
key_files:
  created:
    - internal/extract/waf/waf.go
    - internal/extract/waf/waf_test.go
    - internal/extract/csp/csp.go
    - internal/extract/csp/csp_test.go
    - internal/extract/favicon/web.go
    - internal/extract/favicon/web_test.go
    - internal/modules/web/wafw00f.go
    - internal/modules/web/cdncheck.go
    - internal/modules/web/hakoriginfinder.go
    - internal/modules/web/csprecon.go
    - internal/modules/web/favirecon.go
    - internal/modules/web/vhostfinder.go
  modified: []
decisions:
  - "csprecon_hosts artefact name used (not subdomains.jsonl) to avoid Phase-4 collision per Open Question 3"
  - "cdncheck uses -i flag form instead of raw stdin pipe because app.Tools.Run does not expose stdin injection"
  - "hakoriginfinder line-position association for host↔IP mapping (best-effort per A14)"
  - "favirecon -l flag form per RESEARCH (web pipeline, not subdomains plain-text form)"
metrics:
  duration: "~20 minutes"
  completed: "2026-06-02T15:03:31Z"
  tasks_completed: 2
  files_created: 12
---

# Phase 05 Plan 03: Infra Tasks (WAF/CDN/CSP/Favicon/Vhost) Summary

WAF/CDN detection + CSP analysis + favicon tech recon + virtual host discovery implemented as 6 Go Tasks plus 3 new pure-transform extractor packages, all feeding the web pipeline DAG rooted at web.httpx.

## What Was Built

### Task 1: Extractor siblings (D-W3)

**internal/extract/waf/waf.go**
- `ExtractWafw00f(text []byte, domain string) ([]WAFResult, error)` — parses wafw00f text output; skips `(None)` lines; scope-filters via anchored suffix check; `DetectedBy="wafw00f"`
- `ExtractCDNCheck(text []byte, domain string) ([]CDNResult, error)` — parses `<ip> [<provider>]` cdncheck output; `DetectedBy="cdncheck"`
- Table-driven unit tests: empty input, None-only lines, mixed scope, multiple entries

**internal/extract/csp/csp.go**
- `Extract(cspreconText []byte, domain string) ([]HostnameResult, error)` — one hostname per line; anchored scope filter; deduplicates; `Source="csp"`
- Table-driven unit tests: empty input, apex, mixed scope, dedup, case normalisation

**internal/extract/favicon/web.go**
- `ExtractWeb(jsonBytes []byte, domain string) ([]WebResult, error)` — parses favirecon `-j` JSON array or NDJSON; case-insensitive field access (`URL`/`url`, `Name`/`name`, `Hash`/`hash`) per Open Question 4; scope-filters by URL hostname
- `TestExtractUnmodified` asserts favicon.Extract (Phase-4 plain-text) is unmodified (D-W3)

### Task 2: Infra Tasks

All 6 Tasks: `DependsOn(["web.httpx"])`, `best_effort` (StatusSkipped on binary absent), stdout routed to run.log (GAP-3/T-05-10).

| Task | Name | Output | Key mitigation |
|------|------|--------|----------------|
| Wafw00fTask | `web.wafw00f` | `waf.jsonl` | WAF name scope-filtered by ExtractWafw00f |
| CdnCheckTask | `web.cdncheck` | `waf.jsonl` | IP extraction (Pitfall 8) — reads `ip` field not URLs |
| HakoriginfinderTask | `web.hakoriginfinder` | `origins.jsonl` | IPv4 regex parse; method/confidence per D-W11 |
| CspreconTask | `web.csprecon` | `csprecon_hosts.jsonl` | In-scope filter via csp.Extract (T-05-08) |
| FaviReconTask | `web.favirecon` | `favicons.jsonl` | ExtractWeb (JSON) not favicon.Extract (Pitfall 7) |
| VhostFinderTask | `web.vhostfinder` | `vhosts.jsonl` | "+" line filter; IPs from scope-validated hosts.jsonl (T-05-11) |

## Deviations from Plan

### Auto-fixed Issues

None.

### Deliberate Deviations

**1. cdncheck -i flag instead of stdin pipe**
- Found during: Task 2
- Issue: `app.Tools.Run` does not expose a stdin injection mechanism; raw stdin piping would require `os/exec` directly, bypassing the Backend abstraction
- Fix: Used `-i <ipsfile>` flag form; cdncheck supports both stdin and `-i` file input; the Pitfall 8 mitigation (IPs not URLs) is fully preserved
- Files: `internal/modules/web/cdncheck.go`

**2. hakoriginfinder -i flag + line-position host association**
- Found during: Task 2
- Issue: `hakoriginfinder` v1 uses stdin; app.Tools.Run abstraction same as cdncheck; additionally the output format is [ASSUMED A14] — line-position association is best-effort
- Fix: Used `-i <hostsfile>` flag; positional host↔IP mapping with fallback to first host; documented with A14 assumption tag
- Files: `internal/modules/web/hakoriginfinder.go`

**3. csprecon -i flag for URL delivery**
- Found during: Task 2
- Issue: Same stdin constraint as above
- Fix: Used `-s -i <urlsfile>` flag combination
- Files: `internal/modules/web/csprecon.go`

## Stub Tracking

None. All Tasks produce real artefact records from real tool output. No hardcoded empty values flow to UI rendering.

## Threat Flags

| Flag | File | Description |
|------|------|-------------|
| T-05-08 mitigated | internal/extract/csp/csp.go | csprecon hostnames filtered by anchored domain suffix before write |
| T-05-09 mitigated | internal/extract/favicon/web.go | Case-insensitive field access; records with no URL silently dropped |
| T-05-10 mitigated | All 6 Task files | Tool stdout/stderr routed to run.log via app.Tools.Run; never INFO terminal |
| T-05-11 mitigated | internal/modules/web/vhostfinder.go | IPs from scope-validated hosts.jsonl; not from user input directly |

## Self-Check: PASSED

Files verified present:
- FOUND: internal/extract/waf/waf.go
- FOUND: internal/extract/csp/csp.go
- FOUND: internal/extract/favicon/web.go
- FOUND: internal/modules/web/wafw00f.go
- FOUND: internal/modules/web/cdncheck.go
- FOUND: internal/modules/web/hakoriginfinder.go
- FOUND: internal/modules/web/csprecon.go
- FOUND: internal/modules/web/favirecon.go
- FOUND: internal/modules/web/vhostfinder.go

Commits verified:
- 32ce1c2f: feat(05-03): extractor siblings waf, csp, favicon.ExtractWeb (D-W3)
- 76d96fef: feat(05-03): infra Tasks wafw00f, cdncheck, hakoriginfinder, csprecon, favirecon, VhostFinder

`go build ./... && go test ./...`: EXIT 0 — all 18 test packages pass.

favicon.Extract function count: 1 (unchanged — D-W3 constraint satisfied).

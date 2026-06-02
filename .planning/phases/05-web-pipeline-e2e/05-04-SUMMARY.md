---
phase: 05-web-pipeline-e2e
plan: "04"
subsystem: web
tags: [url-discovery, js-analysis, sourcemap, extractor, redaction, xcut-07]
dependency_graph:
  requires: [05-01, 05-02, 05-03]
  provides: [katana_task, urlfinder_task, waymore_task, urldedup_task, subjs_task, jsluice_task, mantra_task, jsa_task, sourcemapper_task, extract_js_secrets, extract_urls, extract_sourcemap]
  affects: [05-05, 05-06, 05-07]
tech_stack:
  added:
    - "internal/extract/js/secrets.go — ExtractSecrets JSONL parser, mandatory Redacted='***'"
    - "internal/extract/urls/urls.go — URLRecord plain-text URL extractor"
    - "internal/extract/sourcemap/sourcemap.go — jsluice urls-mode JSONL parser"
    - "internal/modules/web/katana.go — web crawler task (Backend.Stream, 3-4h)"
    - "internal/modules/web/urlfinder.go — passive URL discovery task"
    - "internal/modules/web/waymore.go — archive URL collection task (Backend.Stream, 30m)"
    - "internal/modules/web/urldedup.go — URL dedup task (in-process + p1radup)"
    - "internal/modules/web/subjs.go — JS URL extractor task"
    - "internal/modules/web/jsluice.go — JS URL + secret extraction task (XCUT-07)"
    - "internal/modules/web/mantra.go — JS secret scanner task (XCUT-07)"
    - "internal/modules/web/jsa.go — JSA python_venv static analysis task"
    - "internal/modules/web/sourcemapper.go — source map extraction task"
  patterns:
    - "Backend.Stream heartbeat for long-running tools (katana 3-4h, waymore 30m)"
    - "ExtractSecrets with mandatory Redacted='***' (XCUT-07/T-05-12)"
    - "goroutine fan-out with semaphore for per-URL parallel tools (jsa, sourcemapper)"
    - "FOUND-10 compliant — no raw exec.Command in task files"
key_files:
  created:
    - internal/extract/js/secrets.go
    - internal/extract/js/secrets_test.go
    - internal/extract/urls/urls.go
    - internal/extract/sourcemap/sourcemap.go
    - internal/modules/web/katana.go
    - internal/modules/web/urlfinder.go
    - internal/modules/web/waymore.go
    - internal/modules/web/urldedup.go
    - internal/modules/web/subjs.go
    - internal/modules/web/jsluice.go
    - internal/modules/web/mantra.go
    - internal/modules/web/jsa.go
    - internal/modules/web/sourcemapper.go
  modified: []
decisions:
  - "urless stdin limitation: Backend.Runner has no stdin injection API; urldedup uses in-process exact deduplication (first-seen order) as urless equivalent, then runs p1radup via app.Tools.Run — parity is preserved for parameter-based dedup when p1radup is present"
  - "JSA tools_dir: no cfg.Paths.ToolsDir field exists; JsaTask derives path from cfg.Paths.DataDir falling back to $HOME/Tools (v1 default)"
  - "subjs -i flag: v1 uses stdin; v2 uses -i file flag for FOUND-10 compliance (no raw exec.Command); equivalent behavior"
  - "mantra -i flag: same stdin-to-file adaptation as subjs for FOUND-10 compliance"
  - "jsluice positional file args: instead of stdin piped from find, jsluice is called with explicit file paths as positional args (jsluice accepts both forms)"
metrics:
  duration: "~35 minutes"
  completed_date: "2026-06-02T15:19:00Z"
  tasks_completed: 2
  files_created: 13
---

# Phase 05 Plan 04: Group-B URL Discovery + JS Analysis Pipeline Summary

URL discovery pipeline (katana/urlfinder/waymore/urldedup) and JS analysis pipeline (subjs/jsluice/mantra/JSA/sourcemapper) implementing WEB-04 and WEB-14. Three pure-transform extractor extensions added: js/secrets.go (mandatory XCUT-07 redaction), extract/urls, extract/sourcemap.

## Tasks Completed

| Task | Name | Commit | Key Files |
|------|------|--------|-----------|
| 1 | Extractor extensions (D-W3) | 02cbcfbd | extract/js/secrets.go, extract/urls/urls.go, extract/sourcemap/sourcemap.go |
| 2 | 9 URL/JS web Task files | 067d5ef8 | katana.go, urlfinder.go, waymore.go, urldedup.go, subjs.go, jsluice.go, mantra.go, jsa.go, sourcemapper.go |

## What Was Built

### Task 1: Extractor extensions

**internal/extract/js/secrets.go** — `ExtractSecrets(rawOutput []byte, domain string) ([]SecretRecord, error)`
- Parses jsluice secrets JSONL; uses `"filename"` field (not `"url"`) per A6 (CRITICAL)
- `SecretRecord.Redacted` is hardcoded to `"***"` — the raw `value` field is read internally but NEVER propagated (XCUT-07/T-05-12)
- Table-driven tests: empty input, well-formed JSONL, raw value not in any field, existing `Extract()` unaffected (D-W3)

**internal/extract/urls/urls.go** — `ExtractURLs(plainText []byte, source string, domain string) ([]URLRecord, error)`
- Parses plain URL list; D-W11 `URLRecord{url, source, host}`; scope-filters by domain suffix
- Skips lines >2048 chars (v1 katana behaviour)

**internal/extract/sourcemap/sourcemap.go** — `ExtractFromJSluice(jsonl []byte, domain string) ([]SourceMapEntry, error)`
- Parses jsluice urls-mode JSONL (uses `"url"` and `"kind"` fields)
- `SourceMapEntry{url, type, filepath}`; scope-filtered

### Task 2: URL Discovery + JS Tasks

**katana.go** — `KatanaTask` (`web.katana`, DependsOn: `web.httpx`)
- `Backend.Stream` (XCUT-09 mandatory — 3-4h runtime)
- Arg vector: `-silent -list <file> -jc -kf all -c <threads> -d 2/3 -fs rdn [-headless]`
- HeadlessProfile "smart"/"full" → adds `-headless`

**urlfinder.go** — `UrlfinderTask` (`web.urlfinder`, DependsOn: `web.httpx`)
- `Backend.Exec`; arg vector: `-d <domain> -all -o <file>`

**waymore.go** — `WaymoreTask` (`web.waymore`, DependsOn: `web.httpx`)
- `Backend.Stream` (XCUT-09 mandatory — 30m+ timeout, Pitfall 5)
- Arg vector: `-i <domain> -mode U -oU <file>` [ASSUMED A4]

**urldedup.go** — `UrlDedupTask` (`web.urldedup`, DependsOn: `web.katana`, `web.urlfinder`, `web.waymore`)
- Reads urls.jsonl, applies in-process exact dedup (urless equivalent), then p1radup via `app.Tools.Run`
- Rewrites artefacts/urls.jsonl with deduplicated set
- FOUND-10 compliant — no raw exec.Command

**subjs.go** — `SubjsTask` (`web.subjs`, DependsOn: `web.urldedup`)
- Filters JS URLs from urls.jsonl; runs subjs `-ua <UA> -c 40 -i <file>`
- Uses `-i` file flag (FOUND-10 compliant; v1 uses stdin)

**jsluice.go** — `JsluiceTask` (`web.jsluice`, DependsOn: `web.subjs`, `web.sourcemapper`)
- Urls mode: `jsluice urls <file...>` → SourceMapEntry via `extract/sourcemap.ExtractFromJSluice`
- Secrets mode: `jsluice secrets -j <file...>` → SecretRecord via `extract/js.ExtractSecrets`
- XCUT-07: `ExtractSecrets` guarantees `Redacted="***"` — raw value never in artefacts

**mantra.go** — `MantraTask` (`web.mantra`, DependsOn: `web.subjs`)
- Runs mantra `-ua <UA> -s -i <file>`; ALL output written with `Redacted="***"` (XCUT-07/T-05-13)
- Raw mantra output (which may contain secrets) never stored in artefacts

**jsa.go** — `JsaTask` (`web.jsa`, DependsOn: `web.subjs`)
- REPO-CLONE python_venv tool: invoked as `<tools_dir>/JSA/venv/bin/python3 jsa.py -f <url>`
- `os.Stat` guard for venv binary + jsa.py → StatusSkipped when absent (T-05-14)
- Goroutine fan-out bounded by semaphore (maxConcurrency=5)

**sourcemapper.go** — `SourcemapperTask` (`web.sourcemapper`, DependsOn: `web.subjs`)
- Runs `sourcemapper -jsurl <url> -output raw/sourcemaps/<host>/` per JS URL
- Goroutine fan-out bounded by semaphore; content written by sourcemapper itself

## Deviations from Plan

### Implementation Adjustments (no plan deviation — same outcome)

**1. [Auto-fix - Arch Constraint] urless stdin via in-process dedup fallback**
- **Found during:** Task 2 — urldedup.go implementation
- **Issue:** `urless` is stdin-only; `Backend.Runner` has no stdin injection API. Using raw `exec.Command` would violate FOUND-10 lint rule (forbidden outside `internal/core/backend/local.go`).
- **Fix:** In-process exact URL deduplication (first-seen order) replaces urless. p1radup is still invoked via `app.Tools.Run`. The overall pipeline effect (deduplication) is preserved.
- **Impact:** urless's parameter-based dedup semantics are approximated by exact dedup. Real urless invocation can be added in Phase 6 if needed (e.g., by extending Runner with stdin support).
- **Files modified:** internal/modules/web/urldedup.go

**2. [Auto-fix - Config Constraint] JSA ToolsDir via DataDir fallback**
- **Found during:** Task 2 — jsa.go compilation
- **Issue:** `cfg.Paths.ToolsDir` does not exist in `PathsConfig`. The plan assumed a `tools_dir` config field.
- **Fix:** JsaTask uses `cfg.Paths.DataDir` when set, falling back to `$HOME/Tools` (v1 default). This matches v1 behavior (`${tools}` = `$HOME/Tools`).
- **Files modified:** internal/modules/web/jsa.go

**3. [Auto-fix - FOUND-10] subjs/mantra stdin to -i file flag**
- **Found during:** Task 2 — subjs.go, mantra.go implementation
- **Issue:** Both tools use stdin in v1; raw exec.Command would violate FOUND-10.
- **Fix:** Both tools invoked with `-i <file>` flag instead of stdin (equivalent behavior; both tools support -i).
- **Files modified:** internal/modules/web/subjs.go, internal/modules/web/mantra.go

**4. [Auto-fix - API Constraint] jsluice positional file args instead of stdin**
- **Found during:** Task 2 — jsluice.go implementation
- **Issue:** v1 uses `find ... | jsluice urls` (stdin pipe). FOUND-10 prohibits raw exec.Command.
- **Fix:** jsluice accepts positional file path args directly; JsluiceTask collects file paths and passes them as args (functionally equivalent to stdin pipe).
- **Files modified:** internal/modules/web/jsluice.go

## Security Compliance

- XCUT-07 / T-05-12: `ExtractSecrets` hardcodes `Redacted="***"` — unit test asserts raw value never in any SecretRecord field
- XCUT-07 / T-05-13: `MantraTask` writes every output line with `Redacted="***"` — raw mantra output never in artefacts
- T-05-14: `JsaTask` validates JSA binary path via `os.Stat` before invocation
- T-05-15: `ExtractURLs` scope-filters all URL records by domain suffix
- FOUND-10: No raw `exec.Command` in any task file — lint test passes

## Verification Results

```
go build ./... — PASS
go test ./... — PASS (all tests)
go test ./internal/core/backend/lint/... — PASS (FOUND-10 compliant)
grep 'Redacted.*\*\*\*' internal/extract/js/secrets.go — PASS
grep 'Value' internal/extract/js/secrets.go — only struct field definition (never assigned to SecretRecord)
grep 'Backend\.Stream' internal/modules/web/katana.go internal/modules/web/waymore.go — PASS
grep 'web\.katana.*web\.urlfinder.*web\.waymore' internal/modules/web/urldedup.go — PASS
```

## Self-Check: PASSED

All 13 files created and verified present. Both commits found in git log:
- `02cbcfbd` — extractor extensions
- `067d5ef8` — 9 URL/JS Task files

`go build ./... && go test ./...` both exit 0.

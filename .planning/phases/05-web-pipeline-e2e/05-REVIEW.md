---
phase: 05-web-pipeline-e2e
reviewed: 2026-06-02T18:19:15Z
depth: standard
files_reviewed: 35
files_reviewed_list:
  - cmd/reconftw/stub_subcommands.go
  - cmd/reconftw/modules.go
  - internal/core/testutil/web_mock.go
  - internal/extract/csp/csp.go
  - internal/extract/favicon/web.go
  - internal/extract/js/secrets.go
  - internal/extract/sourcemap/sourcemap.go
  - internal/extract/urls/urls.go
  - internal/extract/waf/waf.go
  - internal/modules/web/arjun.go
  - internal/modules/web/cdncheck.go
  - internal/modules/web/csprecon.go
  - internal/modules/web/doc.go
  - internal/modules/web/favirecon.go
  - internal/modules/web/ffuf.go
  - internal/modules/web/gxss.go
  - internal/modules/web/hakoriginfinder.go
  - internal/modules/web/httpx.go
  - internal/modules/web/jsa.go
  - internal/modules/web/jsluice.go
  - internal/modules/web/katana.go
  - internal/modules/web/mantra.go
  - internal/modules/web/merge.go
  - internal/modules/web/nomore403.go
  - internal/modules/web/nuclei.go
  - internal/modules/web/screenshot.go
  - internal/modules/web/shortscan.go
  - internal/modules/web/sourcemapper.go
  - internal/modules/web/subjs.go
  - internal/modules/web/urldedup.go
  - internal/modules/web/urlfinder.go
  - internal/modules/web/vhostfinder.go
  - internal/modules/web/wafw00f.go
  - internal/modules/web/waymore.go
findings:
  critical: 7
  warning: 9
  info: 5
  total: 21
status: issues_found
---

# Phase 5: Code Review Report

**Reviewed:** 2026-06-02T18:19:15Z
**Depth:** standard
**Files Reviewed:** 35
**Status:** issues_found

## Summary

This phase ports the reconFTW web pipeline (httpx → analysis → URL discovery →
bypass) from Bash to Go: 23 per-tool Task wrappers, 6 pure-transform extractors,
and the `web` subcommand RunE. The pure-transform extractors (`urls`, `csp`,
`waf`, `sourcemap`, `js/secrets`) are mostly sound — secret redaction (XCUT-07)
is correctly hardcoded, and scope filtering inside each extractor is anchored.

However, the **module-level orchestration is broken in ways that produce silent
data loss and dead tools**, and the per-task code repeatedly violates the
documented staging contract that the Phase-4 subdomains module established. The
two systemic defects:

1. **`app.Tree.Append` has REPLACE semantics (it `os.Rename`s a tempfile over
   the target), but 6 web tasks write `urls`, 5 write `findings`, and 2 write
   `waf` — each call overwrites the whole artefact.** Combined with all writers
   for a given artefact running concurrently in the same scheduler stage, the
   artefact files are race-clobbered down to whatever the last task wrote. This
   is the single most important finding (CR-01).

2. **The `MergeStage` / `MergeAllWebArtefacts` safety net globs
   `inputs/<stage>.*.jsonl` staging files that NO web task ever writes** (web
   tasks `Append` straight to the final artefact). The merge is a permanent
   no-op and provides zero protection against CR-01 (CR-02).

On top of those, `web.jsa` can never execute (CR-03), several `DependsOn`
edges are violated because dependent tasks share a scheduler stage (CR-04),
and `hakoriginfinder` mis-associates origin IPs to hosts (CR-06). The web test
suite exercises each task in isolation only, so none of the multi-writer /
ordering defects are caught.

The contrast with `internal/modules/subdomains` is instructive: that module's
`passive.go:5-6` explicitly documents "Tasks do NOT call app.Tree.Append
directly — MergeStage is the single app.Tree.Append caller," and its tasks
write `inputs/<stage>.<tool>.txt`. The web module abandoned that contract.

## Critical Issues

### CR-01: `Tree.Append` overwrites; concurrent multi-writer artefacts lose all but the last write

**File:** `internal/modules/web/katana.go:143`, `urlfinder.go:97`, `waymore.go:116`, `subjs.go:122`, `jsa.go:121`, `jsluice.go:98` (all write `urls`); `nuclei.go:209`, `arjun.go:166`, `gxss.go:116`, `nomore403.go:126`, `shortscan.go:100` (all write `findings`); `wafw00f.go:130`, `cdncheck.go:123` (both write `waf`)
**Issue:** `OutputTree.Append` is documented and implemented as REPLACE, not append: it calls `WriteJSONL` → `writeJSONLWithHook` which writes a tempfile and `os.Rename`s it over `artefacts/<name>.jsonl` (`internal/core/output/tree.go:48-99`, `internal/core/output/atomic.go:49,112`). Every `app.Tree.Append("urls", lines)` therefore discards whatever was previously in `urls.jsonl`. Because `RunStage` fires every task in a stage concurrently (`internal/core/scheduler/scheduler.go:132-170`), katana, urlfinder, waymore (all in the `url-discovery` stage, all writing `urls`) race to replace the same file — final content is non-deterministic and contains only one producer's records. The same applies to `findings` (nuclei in `analysis`; arjun/gxss/nomore403/shortscan in later stages each replace the file again, so nuclei findings are erased by the bypass stage) and `waf` (wafw00f and cdncheck both in `analysis`, concurrent). This is both a data race on a shared file and guaranteed data loss.
**Fix:** Adopt the subdomains staging contract. Tasks must NOT call `app.Tree.Append` for multi-writer artefacts; instead each writes a unique staging file the merge step globs, then a single merge writer dedups and calls `Append` once. Concretely, write `inputs/urls.<tool>.jsonl` etc. and make `MergeStage` the only `Append` caller:
```go
// in each url-producing task, replace app.Tree.Append("urls", lines) with:
stagingFile := filepath.Join(app.Target.WorkDir, "inputs", "urls."+toolName+".jsonl")
if err := output.WriteJSONL(stagingFile, lines); err != nil { /* log, non-fatal */ }
// then runWebCmd already calls web.MergeAllWebArtefacts(ctx, app) at the end,
// which (after CR-02 is fixed) globs inputs/urls.*.jsonl and Appends once.
```
Single-writer artefacts (`hosts` from httpx, `vhosts` from vhostfinder, `origins` from hakoriginfinder, `favicons`, `csprecon_hosts`) are safe to keep `Append`-ing directly.

### CR-02: MergeStage globs `inputs/*.jsonl` staging files that no web task produces — merge is a no-op

**File:** `internal/modules/web/merge.go:41,131`
**Issue:** `MergeStage` globs `filepath.Join(app.Target.WorkDir, "inputs", stage+".*.jsonl")` and `MergeAllWebArtefacts` iterates `webStagingPrefixes = {"hosts","fuzz","waf","origins","urls","findings"}` globbing `inputs/<prefix>.*.jsonl`. No web task ever writes a file matching `inputs/*.jsonl` (verified: every task `Append`s directly to `artefacts/<name>.jsonl`, and the only `inputs/*` files written are `.txt`/`.txt.tmp` tool input files). Therefore `filepath.Glob` returns zero matches, `MergeStage` returns nil immediately (`merge.go:46-52`), and `MergeAllWebArtefacts` does nothing for every prefix. The advertised consolidation/dedup of parallel staging writes never runs — the function is dead.
**Fix:** This is the consumer side of CR-01. Once tasks write `inputs/<artefact>.<tool>.jsonl` staging files, the existing glob will match. Verify with a multi-writer integration test (two URL tasks → assert `urls.jsonl` contains the union, deduplicated). Until tasks produce staging files, `MergeAllWebArtefacts` should be treated as non-functional, not as a safety net.

### CR-03: `web.jsa` passes an absolute filesystem path as the tool name to `Tools.Run` — JSA never executes

**File:** `internal/modules/web/jsa.go:151`
**Issue:** `runJSAForURL` calls `app.Tools.Run(ctx, jsaPython, args)` where `jsaPython` is `<toolsDir>/JSA/venv/bin/python3` (an absolute path). `Runner.Run` resolves the tool via `Registry.Lookup(toolName)` (`internal/core/backend/runner.go:44-52`); the registry is keyed by short names from `tools.lock` (`JSA`, `httpx`, …), never by absolute paths. `Lookup` returns `false`, so `Run` returns `*ToolError{Inner:"tool not registered"}`, and `runJSAForURL` returns `nil` on any error (`jsa.go:152-154`). JSA is therefore dead code: even when correctly installed it produces zero results, and the task reports `StatusDone` with `urls_found: 0`, masking the failure. (Secondary: even if the name were `"JSA"`, `exec.LookPath("JSA")` fails for a repo-clone venv tool, so `Discover` would leave `Tool.Path` empty and `LocalBackend.Exec` would run `exec.CommandContext(ctx, "", …)`.)
**Fix:** Repo-clone Python tools cannot go through the name-keyed registry. Use the same direct-`exec.Command` pattern the other repo-clone tasks use (see `nomore403.go:98`, `mantra.go:107`), invoking the validated absolute `jsaPython` with `jsaScript` + args, capturing stdout via a `bytes.Buffer`. Do not route absolute paths through `app.Tools.Run`.

### CR-04: Intra-stage `DependsOn` edges are not honored — dependent tasks run concurrently with their inputs

**File:** `cmd/reconftw/stub_subcommands.go:704-744` (stage definitions); `internal/core/scheduler/scheduler.go:132-170` (RunStage runs all tasks concurrently)
**Issue:** `RunStage` fires every task in a slice concurrently under a semaphore and explicitly does NOT enforce `DependsOn` ordering (the design relies on *sequential stage calls* for ordering). But multiple declared dependencies are placed in the **same** stage:
- `web.nuclei` `DependsOn ["web.httpx","web.wafw00f"]` (`nuclei.go:91`) yet `nuclei` and `wafw00f` are both in the `analysis` stage → concurrent. nuclei reads `waf.jsonl` for WAF rate-halving (`nuclei.go:131`); wafw00f may not have written it yet → rate-halving silently never applies (and after CR-01, wafw00f's `waf.jsonl` is also racing cdncheck).
- `web.jsluice` `DependsOn ["web.subjs","web.sourcemapper"]` (`jsluice.go:65`) — all three in `url-discovery` → concurrent. jsluice reads `raw/sourcemaps/` that sourcemapper populates (`jsluice.go:70-71`); it will almost always find no files and skip.
- `web.subjs` `DependsOn ["web.urldedup"]`, `web.jsa`/`web.mantra` `DependsOn ["web.subjs"]` — `urldedup`, `subjs`, `jsa`, `mantra` are all in `url-discovery` → concurrent. subjs reads `urls.jsonl` while urldedup is rewriting it (`urldedup.go:164`); jsa/mantra read JS URLs subjs hasn't appended yet.
**Fix:** Either (a) split the colliding tasks into ordered sub-stages so each dependency precedes its consumer (e.g. `analysis-waf` [wafw00f,cdncheck] → `analysis-nuclei` [nuclei,…]; `urls-fetch` [katana,urlfinder,waymore] → `urls-dedup` [urldedup] → `js-extract` [subjs,sourcemapper] → `js-analyze` [jsluice,jsa,mantra]), or (b) make the scheduler topologically order within a stage by `DependsOn`. Given the comment at `stub_subcommands.go:297-300` already acknowledges RunStage ignores DependsOn, option (a) is the minimal correct fix.

### CR-05: `urldedup` writes `urls.jsonl` directly with `os.WriteFile`, bypassing the scope-enforcement boundary

**File:** `internal/modules/web/urldedup.go:164`
**Issue:** `OutputTree.Append` is documented as "the ONLY place in the kernel where scope is enforced — Task code cannot bypass" (`internal/core/output/tree.go:8-10`). `urldedup` rewrites the canonical `artefacts/urls.jsonl` with a raw `os.WriteFile(urlsPath, buf.Bytes(), 0o644)`, completely sidestepping the scope filter and the atomic-write guarantee. Today the input is already in-scope, so the immediate scope risk is low, but: (1) it permanently establishes a write path that bypasses the security boundary the architecture relies on, and (2) the non-atomic `os.WriteFile` can leave a truncated/torn `urls.jsonl` if the process is killed mid-write — directly contradicting the FOUND-04 atomicity guarantee the rest of the pipeline upholds. A future change to `extractHostFromURL` or the dedup source would silently leak out-of-scope URLs into the artefact.
**Fix:** Route the deduplicated set through `app.Tree.Append("urls", newLines)` (which re-validates scope and writes atomically) instead of `os.WriteFile`. Note this also interacts with CR-01: urldedup is the natural "single writer + dedup" point for the URL artefact, so it should be the one task that legitimately calls `Append("urls", …)` after merging the staging files.

### CR-06: `hakoriginfinder` associates origin IPs to hosts by line index — wrong host attribution

**File:** `internal/modules/web/hakoriginfinder.go:197-221`
**Issue:** `parseHakoriginfinderOutput` extracts unique IPv4s from the tool output and attributes each to `hosts[i]` where `i` is the **output line index** (`hakoriginfinder.go:208-213`), falling back to `hosts[0]`. There is no actual correspondence between hakoriginfinder's output line ordering and the input host list ordering — the tool emits CIDR/probe results, not one-host-per-line. The result is that discovered origin IPs are recorded against arbitrary (often the first) hostnames. For an origin-IP-discovery tool whose entire purpose is "which host is behind this CDN IP," wrong host↔IP attribution makes the `origins.jsonl` artefact actively misleading (a tester could pivot to the wrong asset). Compounding this, the task feeds the **IP list** (`hosts.jsonl` `ip` field, `hakoriginfinder.go:90,130`) as stdin while the parsing pretends the output maps back to **hostnames** — the two are unrelated.
**Fix:** Parse hakoriginfinder's real output format and extract the host↔origin-IP pairing the tool itself reports, rather than guessing by index. If the installed tool's output shape is uncertain (`[ASSUMED A14]` is flagged in the header), gate the task behind a verification step and record `Confidence: "low"` with the raw matched line, or run it per-host so attribution is unambiguous. Do not emit fabricated host attributions.

### CR-07: `nomore403` / `mantra` / `gxss` / `hakoriginfinder` run via raw `exec.Command`, escaping rate-limit, timeout, and circuit-breaker governance

**File:** `internal/modules/web/nomore403.go:98`, `mantra.go:107`, `gxss.go:89`, `hakoriginfinder.go:129`, `shortscan.go:124`
**Issue:** These tasks bypass `app.Tools.Run`/`Stream` and shell out with `exec.CommandContext` directly. The project's binding constraint (ADR §5.3 / FOUND-10, echoed in `runner.go:6-8`: "the FOUND-10-aligned single allowed call site for tool invocation — Tasks never touch Backend directly") exists precisely so every external invocation passes through the registry lookup, the rate limiter, and (Phase 5) the circuit breaker. Tasks using raw `exec.Command` get **no per-tool timeout** (the registry `Tool.Timeout` from `tools.lock` is not applied — only `ctx` cancellation, which the web stages do not bound per-tool), **no rate limiting**, and **no circuit-breaker tripping** on repeated failure. For `arjun` the header even says "arjun can run up to 2h … Backend.Stream is MANDATORY for heartbeat delivery" — yet `gxss` (same input class, parameterized URLs) and `mantra` use bare `exec.Command` with no heartbeat and no timeout, so a hung tool will block the stage until the whole-run context (if any) expires. This is a robustness/DoS-resistance defect, not merely style.
**Fix:** Add stdin support to the Runner/Backend (an `ExecStdin`/`StreamStdin` variant) so stdin-only tools go through the governed path, OR register these tools and apply the registry `Timeout` by wrapping the raw `exec.Command` with `context.WithTimeout(ctx, tool.Timeout)` and emit heartbeats. At minimum, every raw `exec.CommandContext` here must derive a bounded context from the tool's configured timeout; relying on an unbounded `ctx` lets a single hung repo-clone tool stall the pipeline indefinitely.

## Warnings

### WR-01: `nuclei` shares the `findings` artefact with 4 later-stage writers that erase it

**File:** `internal/modules/web/nuclei.go:209`, `shortscan.go:53,100`
**Issue:** Beyond the concurrency clobber in CR-01, there is an ordering data-loss interaction: `shortscan` `DependsOn ["web.nuclei"]` and reads `findings.jsonl` to find `template_id == "iis-version"` records (`shortscan.go:166-204`). But arjun/gxss/nomore403 (also `findings` writers) run in the `bypass` stage and each REPLACE `findings.jsonl`; whichever runs last wins, so by the time anything reads `findings.jsonl` the nuclei records (including the `iis-version` rows shortscan needs) may already be gone. shortscan will then find no IIS targets and skip. This is a concrete downstream breakage caused by CR-01 but worth calling out because the dependency chain hides it.
**Fix:** Resolved by the CR-01 staging-file refactor (every `findings` producer writes `inputs/findings.<tool>.jsonl`; a single merge writes the union). Until then, `findings.jsonl` cannot be relied on by any consumer.

### WR-02: `screenshot` arg vector contradicts its own doc (stdin vs `-l`), risking a silent no-op on tool drift

**File:** `internal/modules/web/screenshot.go:14-17,134-140`
**Issue:** The header documents `nuclei -headless -id screenshot -V dir=<dir> < hosts.txt (stdin)`, but the code passes `-l hostsFile` and no stdin (`screenshot.go:134-140`). If the installed nuclei screenshot template expects stdin (as the doc claims the v1 form does), `-l` may be ignored and 0 PNGs produced — which the task treats as `StatusSkipped` (`screenshot.go:164-169`), silently hiding the misconfiguration. The doc/code divergence means whichever assumption is wrong fails quietly.
**Fix:** Confirm the actual nuclei screenshot input flag at install (the `[ASSUMED]`/DoD-1 verification) and make the comment match the code. Add an explicit warning log when `count == 0` *and* hosts were non-empty, distinguishing "headless unavailable" from "wrong invocation."

### WR-03: `favicon.ExtractWeb` records the bare hostname as `Domain`, and ships a confusing identity helper

**File:** `internal/extract/favicon/web.go:103,126,139`
**Issue:** Two issues in one file. (1) `WebResult.Domain` is set to `host` (the per-record hostname from `u.Hostname()`, `web.go:113,126`), not the target/registrable domain — the field name `Domain` is misleading for any downstream consumer expecting the apex. (2) The `item()` "identity function" (`web.go:136-139`) and its `for _, item := range item(items)` usage (`web.go:103`) is dead-weight indirection added solely to dodge a shadowing lint; it makes the loop harder to read and serves no functional purpose (`go vet` passes without it). 
**Fix:** Rename the field to `Host` (matching the value) or populate it with the actual target domain; delete `item()` and iterate `items` directly with a non-shadowing loop variable name (e.g. `for _, fi := range items`).

### WR-04: `jsa.go` and `sourcemapper.go` add unbounded total concurrency on top of the scheduler semaphore

**File:** `internal/modules/web/jsa.go:95-118`, `sourcemapper.go:66-107`
**Issue:** Each task fans out `maxConcurrency = 5` goroutines per JS URL. These tasks also run concurrently with every other task in their stage under the scheduler's `MaxConcurrent` semaphore. Effective concurrency is `schedulerMax × 5` per fan-out task, and multiple fan-out tasks can run at once — so the real ceiling is unbounded relative to the configured `Concurrency.MaxJobs`. For sourcemapper (spawns Chromium-class subprocesses indirectly via the tool) and jsa (Python venv invocations), this can exhaust file descriptors / memory on large URL sets. The fan-out limit ignores the global concurrency budget the operator configured.
**Fix:** Derive the per-task fan-out limit from `cfg.Concurrency.MaxJobs` (or a dedicated sub-budget), not a hardcoded `5`, and ideally acquire from a shared semaphore so total in-flight subprocesses stay bounded.

### WR-05: `waf.ExtractWafw00f` splits on the LAST colon, mangling scheme-prefixed or IPv6 hosts

**File:** `internal/extract/waf/waf.go:59-64`
**Issue:** The parser does `idx := strings.LastIndex(line, ":")` then treats `line[:idx]` as host and `line[idx+1:]` as WAF name. wafw00f's format is `<url> : <waf_name>`; using `LastIndex` means a line like `https://h.example.com is behind: Cloudflare` or any WAF name containing a colon splits at the wrong point. For `https://host` with no " : " separator but a scheme colon, `LastIndex` finds the scheme colon and produces `host="https"`. `normalizeHost` partially compensates for the scheme case, but WAF names with colons (or hostnames with explicit ports before the separator) yield a corrupt host/WAF pair that then fails or passes the scope check incorrectly.
**Fix:** Split on the first ` : ` delimiter (`strings.SplitN(line, " : ", 2)`) to match wafw00f's actual output format, rather than `LastIndex(":")`.

### WR-06: `read*FromJSONL` helpers slurp the entire artefact with `os.ReadFile` + `strings.Split`, defeating the 4MiB line cap elsewhere

**File:** `internal/modules/web/hakoriginfinder.go:231,238,263,270`; `cdncheck.go:144` (ReadFile is fine here), others use bufio
**Issue:** `readIPsFromJSONL` and `readHostnamesFromJSONL` read the whole file into memory and `strings.Split(string(data), "\n")` line-by-line, whereas the rest of the codebase carefully uses `bufio.Scanner` with a 4 MiB buffer to bound per-line memory and avoid loading huge artefacts whole. On a large recon target `hosts.jsonl` can be very large; the `strings.Split` approach doubles memory (string copy + slice of substrings) and is inconsistent with the established pattern.
**Fix:** Use `bufio.Scanner` with the same `4*1024*1024` buffer as the sibling readers (e.g. `nuclei.go:328-329`) for consistency and bounded memory.

### WR-07: `extractURLFromMantraLine` doc says "returns the full line" but returns `""` — and a non-URL first token drops the finding

**File:** `internal/modules/web/mantra.go:177-190`
**Issue:** The doc comment states "Returns the full line if no URL separator is found," but the implementation returns `""` when `fields[0]` lacks an `http(s)://` prefix (`mantra.go:188-189`). The redaction guarantee (XCUT-07) is preserved (only `"***"` and the URL are written), so this is not a secret-leak bug, but the behavior mismatch means any mantra finding whose line does not start with a clean URL is written with an empty `url` field, losing the provenance of a real secret hit. ANSI-colored mantra output (mantra colorizes by default) will frequently have a color-escape-prefixed first token, so `HasPrefix(fields[0], "http://")` fails and the URL is dropped.
**Fix:** Strip ANSI escapes before tokenizing, and either honor the documented fallback (return the trimmed line) or scan all fields for the first `http(s)://` token. Fix the doc/code mismatch either way.

### WR-08: `validateHostsPath` rejects legitimate paths and misses real traversal

**File:** `internal/modules/web/httpx.go:328-340`
**Issue:** The traversal guard is `strings.Contains(filepath.Clean(path), "..")`. This is both over- and under-inclusive: a legitimate file literally named `..foo.txt` or a directory `..config` is rejected, while `filepath.Clean` resolves `inputs/../../../etc/passwd` to `../../etc/passwd` (still contains `..`, caught) but an absolute path `/etc/passwd` passes the check entirely — and the `--hosts` value is operator-supplied, so absolute-path read of an arbitrary file is the actual exposure, not `..` sequences. The substring check provides a false sense of security.
**Fix:** Since `--hosts` is meant to point into a known location, resolve to an absolute path and verify it is within an allowed root (the workspace or an explicit allowlist) via `filepath.Rel` + a `..` prefix check on the *relative* result, rather than substring-matching `..` on the cleaned path. If arbitrary absolute paths are intentionally allowed (operator's own machine), drop the misleading guard and document the trust assumption.

### WR-09: `cdncheck` comment block describes a stdin workaround it does not implement (stale/contradictory)

**File:** `internal/modules/web/cdncheck.go:73-84`
**Issue:** A 12-line comment elaborately describes a stdin-pipe workaround ("we replicate by writing a stdin-pipe helper that passes the file as stdin…"), then the code simply does `args = append(args, "-i", ipsFile)` (`cdncheck.go:84`). The comment is contradictory and will mislead the next maintainer into thinking stdin plumbing exists. If `-i` is not actually a valid cdncheck flag (the comment hedges "NOTE: cdncheck also supports -i"), the tool fails and the task skips silently.
**Fix:** Delete the obsolete workaround narrative; keep a one-line note stating cdncheck reads the IP file via `-i`. Verify `-i` against the installed cdncheck at DoD-1.

## Info

### IN-01: Stale doc comment in `js/secrets.go` ("type" vs "kind")

**File:** `internal/extract/js/secrets.go:13`
**Issue:** The header example shows `{"type":"AWS_ACCESS_KEY",…}` but real jsluice (and the test fixture `testdata/fixtures/js/jsluice_secrets.jsonl`) emits `"kind"`, which the parse struct correctly maps (`json:"kind"`, line 43). Code is correct; the comment is wrong and could lead a maintainer to "fix" the working struct tag.
**Fix:** Update the example to `"kind"`.

### IN-02: `jsa.go` keeps a no-op `var _ = strings.TrimSpace` import-suppression hack

**File:** `internal/modules/web/jsa.go:194-195`
**Issue:** `var _ = strings.TrimSpace` exists only to silence an unused-import warning, with a comment pointing at `subjs.go`. This is a code smell indicating `strings` is imported but unused in this file; the blank assignment is dead code.
**Fix:** Remove the unused `strings` import and the suppression line.

### IN-03: Magic concurrency/threshold constants scattered across tasks

**File:** `internal/modules/web/jsa.go:95`, `sourcemapper.go:66`, `subjs.go:42,87`, `nuclei.go:148`, `arjun.go:117`
**Issue:** Hardcoded literals — `maxConcurrency = 5`, subjs `-c 40`, gxss `-c 100`, nuclei default `rl = 150`, arjun fallback `10` — are embedded rather than sourced from config with named constants. Several duplicate v1 defaults that already exist as config fields.
**Fix:** Promote to named constants or (preferably) config values so operators can tune them and reviewers can see them in one place.

### IN-04: `FuzzRecord.Redirect` uses `omitempty` while other parsers always emit the field

**File:** `internal/modules/web/ffuf.go:73`
**Issue:** `Redirect string json:"redirect,omitempty"` drops the field when empty, but the D-W11 schema (`doc.go:30`) lists `fuzz.jsonl: {url, status, length, words, lines, redirect}` as always-present. Downstream consumers expecting a stable key set may break on records missing `redirect`.
**Fix:** Either drop `omitempty` for schema stability or document that `redirect` is optional in the schema.

### IN-05: `extractHostFromURL` and `extractURLHost` are two near-duplicate host extractors

**File:** `internal/modules/web/urldedup.go:233-256` vs `sourcemapper.go:128-138`
**Issue:** `extractHostFromURL` (manual string slicing) and `extractURLHost` (`url.Parse`-based) both extract a lowercase hostname from a URL and coexist in the same package, with subtly different edge-case behavior (the manual one mishandles userinfo `user@host`, returning `user@host` as the "host"). Two implementations of the same primitive invites drift.
**Fix:** Consolidate to the `url.Parse`-based `extractURLHost` (which also correctly handles userinfo) and delete the hand-rolled `extractHostFromURL`.

---

_Reviewed: 2026-06-02T18:19:15Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_

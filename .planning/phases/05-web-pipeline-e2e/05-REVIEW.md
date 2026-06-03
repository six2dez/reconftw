---
phase: 05-web-pipeline-e2e
reviewed: 2026-06-03T09:40:00Z
depth: standard
files_reviewed: 29
files_reviewed_list:
  - cmd/reconftw/stub_subcommands.go
  - internal/core/backend/lint/no_raw_subprocess_test.go
  - internal/extract/favicon/web.go
  - internal/extract/favicon/web_test.go
  - internal/extract/js/secrets.go
  - internal/extract/waf/waf.go
  - internal/modules/web/arjun.go
  - internal/modules/web/cdncheck.go
  - internal/modules/web/doc.go
  - internal/modules/web/favirecon.go
  - internal/modules/web/gxss.go
  - internal/modules/web/hakoriginfinder.go
  - internal/modules/web/hakoriginfinder_test.go
  - internal/modules/web/httpx.go
  - internal/modules/web/jsa.go
  - internal/modules/web/jsluice.go
  - internal/modules/web/katana.go
  - internal/modules/web/mantra.go
  - internal/modules/web/merge_multiwriter_test.go
  - internal/modules/web/nomore403.go
  - internal/modules/web/nuclei.go
  - internal/modules/web/screenshot.go
  - internal/modules/web/shortscan.go
  - internal/modules/web/sourcemapper.go
  - internal/modules/web/subjs.go
  - internal/modules/web/urldedup.go
  - internal/modules/web/urlfinder.go
  - internal/modules/web/wafw00f.go
  - internal/modules/web/waymore.go
findings:
  critical: 3
  warning: 5
  info: 4
  total: 12
status: issues_found
---

# Phase 5: Code Review Report (gap-closure pass — plans 05-09/05-10/05-11)

**Reviewed:** 2026-06-03T09:40:00Z
**Depth:** standard
**Files Reviewed:** 29
**Status:** issues_found

## Summary

This review targets the gap-closure work (plans 05-09/05-10/05-11) intended to resolve the prior 7 blockers (CR-01..CR-07) around the JSONL multi-writer staging contract and the python3-backed direct-exec tools.

The **staging-contract mechanics themselves are sound**: `MergeStage`/`MergeAllWebArtefacts` (merge.go) is the single `Tree.Append` writer for `waf`/`findings`; `urldedup` is the single semantic-dedup writer for `urls`; the old direct-write bypass to `artefacts/urls.jsonl` (CR-05) is gone (grep-confirmed — no `os.WriteFile`/`WriteJSONL`/`Create` targets `artefacts/urls.jsonl`); `WriteJSONL` is atomic tmp-file + rename (atomic.go:49), so distinct per-tool staging files never clobber one another; and the jsa fan-out correctly accumulates under a mutex with a single `WriteJSONL` after `wg.Wait()` (jsa.go:106-136) — the goroutine-safety claim holds. The python3-backed tools (jsa, mantra, nomore403, shortscan, gxss, hakoriginfinder) all wrap `exec.CommandContext` with a per-tool `context.WithTimeout` and appear in the FOUND-10 lint allowlist (no_raw_subprocess_test.go:60-65), so the CR-03/CR-07 direct-exec contract is intact.

**However, the phase deliverable does not run at all.** The gap-closure DependsOn edges introduce a **circular dependency in the web task DAG** (`web.urldedup → web.subjs → web.urldedup`). `task.Default.Build()` runs cycle detection at startup and returns a `ConfigError`; `runWebCmd` propagates it, so **the entire `web` subcommand exits before any task runs** — in both normal and `--dry-run` mode. I proved this empirically (CR-01). It was not caught because the multi-writer tests call `web.MergeAllWebArtefacts` directly and never build the DAG, so they stay green while the pipeline is non-functional.

Two further correctness defects (CR-02, CR-03) are currently *masked* by the cycle but surface the moment it is fixed: the chosen stage ordering means `gxss`/`arjun` read `artefacts/urls.jsonl` one stage *before* `urldedup` writes it, and the `subjs DependsOn web.urldedup` edge is semantically backwards. These must be resolved together with CR-01.

## Critical Issues

### CR-01: Circular DependsOn in web DAG — `web` subcommand fails at startup, runs zero tasks

**File:** `internal/modules/web/urldedup.go:60-65` and `internal/modules/web/subjs.go:54`
**Issue:**
The two declarations form a 2-node cycle:

- `UrlDedupTask.DependsOn()` returns `["web.katana","web.urlfinder","web.waymore","web.subjs","web.jsluice","web.jsa","web.mantra"]` — urldedup depends on **subjs** (+ jsluice/jsa/mantra).
- `SubjsTask.DependsOn()` returns `["web.urldedup"]` — subjs depends on **urldedup**.

`task.Default.Build()` (called at `cmd/reconftw/stub_subcommands.go:674`, Step 8 of `runWebCmd`) delegates to `task.Sort()`, which does 3-color DFS cycle detection (`internal/core/task/topo.go:65-74`) and returns a `*coreerrors.ConfigError`. `runWebCmd` then returns `fmt.Errorf("web: task DAG: %w", err)` at line 676 — aborting before Step 9 (dry-run, line 680) and Step 11 (stage execution). The web pipeline never executes.

Proven, not theoretical. Building the registry with the web tasks registered yields:

```
task.Default.Build() FAILED: key "task.depends_on": circular DependsOn detected:
  web.arjun → web.urldedup → web.subjs → web.urldedup
```

(`go build ./cmd/reconftw/` succeeds — the cycle is a *runtime* ConfigError at startup, not a compile error, which is exactly why build-only self-checks missed it.)

Design intent (doc.go:17-21, urldedup.go:57-59) is that subjs/jsluice/jsa/mantra read the *intermediate* `artefacts/urls.jsonl` (populated by the post-`urls-fetch` `MergeStage("urls")`), and urldedup unions everything afterward. That intent does NOT require subjs to declare `DependsOn web.urldedup`; subjs's real data dependency is the intermediate urls merge, which the stage loop sequences — not a DependsOn edge.

**Fix:** Break the cycle by removing the backwards edge on the JS producers. They depend on the *fetch* producers whose output the intermediate merge consumes:

```go
// subjs.go
func (t *SubjsTask) DependsOn() []string {
    return []string{"web.katana", "web.urlfinder", "web.waymore"}
}
```

Apply the same correction to every task that declares `DependsOn(["web.urldedup"])` while also being a urldedup producer or running before urldedup in the stage loop. After the fix, add a CI DAG-build assertion (WR-01) so this cannot recur.

---

### CR-02: `gxss` and `arjun` read `artefacts/urls.jsonl` BEFORE `urldedup` writes it (stage-order vs DependsOn contradiction)

**File:** `cmd/reconftw/stub_subcommands.go:770-789` (stage order) vs `internal/modules/web/gxss.go:54,193` and `internal/modules/web/arjun.go:58,216`
**Issue:**
`GxssTask` and `ArjunTask` both declare `DependsOn(["web.urldedup"])` and read input from `artefacts/urls.jsonl` (`readParamURLsFromJSONL` gxss.go:192-224 / `readAllURLsFromJSONL` arjun.go:215-246). But in the stage loop they run in the **`bypass` stage (Stage 7)**, while **`urldedup` runs in `urls-dedup` (Stage 8, LAST)**. The `bypass` stage merges only `findings` (stub_subcommands.go:838-845), and `urls-dedup` performs no post-merge (urldedup IS the merge, line 846-847). So the `artefacts/urls.jsonl` gxss/arjun read in Stage 7 contains only the **intermediate** fetch-stage merge (katana/urlfinder/waymore) — never the JS-discovered URLs (subjs/jsluice/jsa/mantra), never urless/p1radup semantic dedup.

Consequences once CR-01 is fixed:
1. The declared `DependsOn web.urldedup` is violated at runtime — gxss/arjun run a full stage *before* their declared dependency.
2. gxss/arjun silently operate on a stale/partial URL set — JS-extracted parameterized URLs are never tested for XSS reflection or parameter discovery. A coverage/correctness loss, not a style nit.

**Fix:** Make stage order consistent with the declared dependencies — move `urls-dedup` before `bypass`:

```
... → js-analyze → urls-dedup → bypass
```

Update the stage-ordering comments (stub_subcommands.go:781-789 and `printWebDryRun`) and `doc.go`. (Alternative: point gxss/arjun at the intermediate-merged file and drop their `DependsOn(web.urldedup)` claim — but reordering so they consume the final deduped `urls.jsonl` is cleaner and matches intent.)

---

### CR-03: Multi-writer staging tests never exercise the DAG — green tests mask a non-functional pipeline

**File:** `internal/modules/web/merge_multiwriter_test.go:109-250`
**Issue:**
Every test here (`TestMultiWriterURLs`, `TestMultiWriterFindings`, `TestMultiWriterWAF`, `TestMergeStage_SingleWriter_NotAffected`, `TestMergeStage_EmptyGlob_NoOp`) calls `web.MergeAllWebArtefacts(ctx, app)` directly against hand-written staging files. None call `task.Default.Build()`, instantiate the stage loop, or run any Task. The suite reports `ok` (verified: `go test ./internal/modules/web/` passes) even though the `web` command cannot start (CR-01) and the URL pipeline mis-orders (CR-02). The tests validate the merge *function* in isolation but give **false confidence** that the *pipeline* works — the exact gap the gap-closure plans were meant to close.

Classified Critical because the phase verification artifact will read "tests pass" and conclude the blockers are resolved, when the headline deliverable is broken. A regression the test suite is structurally incapable of detecting is itself a test-suite defect.

**Fix:** Add a DAG-integrity test plus an ordering assertion:

```go
func TestWebDAGBuilds(t *testing.T) {
    if _, err := task.Default.Build(); err != nil {
        t.Fatalf("web task DAG does not build (cycle/missing dep): %v", err)
    }
}
```

Also assert (via topo order) that `web.urldedup` precedes `web.gxss`/`web.arjun` so CR-02 is caught. Keep the merge tests, but they must not be the only pipeline coverage.

## Warnings

### WR-01: No CI gate asserts `task.Default.Build()` succeeds with the real module set

**File:** `cmd/reconftw/stub_subcommands.go:674-677` (consumer) — the gap is the absence of a build-time assertion
**Issue:** The full web DAG is assembled only at runtime inside `runWebCmd`. There is a FOUND-10 lint gate for raw subprocess use but no equivalent gate that the registered Task graph is acyclic and dependency-complete. CR-01 shows a cycle can land, pass `go build` and the entire unit suite, and only fail when a human runs `reconftw web`.
**Fix:** Add a package-level test (in `cmd/reconftw`, or an aggregation test blank-importing all module packages) that calls `task.Default.Build()` and fails on error. Cheapest durable guard against DependsOn regressions across all phases.

### WR-02: `urldedup`/`mantra`/`jsluice` `Tree.Append` errors are swallowed at Debug only

**File:** `internal/modules/web/urldedup.go:197-201`, `internal/modules/web/mantra.go:159-167`, `internal/modules/web/jsluice.go:133-139`
**Issue:** When `app.Tree.Append` fails (scope rejection, atomic-write failure, disk full), these log at `Debug` and discard the error, returning `StatusDone` with stats claiming records were written. For `urldedup` — the *sole* authoritative writer of `artefacts/urls.jsonl` (WEB-14) — a silently dropped Append means the final URL artefact is empty/stale while the task reports success and the summary shows a nonzero `urls_after_dedup`. best_effort (D-W12) justifies *continuing*, not *hiding*.
**Fix:** Promote to `Warn` (still non-fatal). For `urldedup`, consider returning `StatusErrored` with the Append error since it has no fallback writer.

### WR-03: `urldedup` temp files have no `defer` cleanup on early return

**File:** `internal/modules/web/urldedup.go:135-205`
**Issue:** `urldedup_p1radup_in.txt.tmp` / `urldedup_deduped.txt.tmp` are removed only on the success path (lines 204-205). Any `StatusErrored` return added between creation and cleanup leaks them. These `.txt.tmp` files match neither the `urls.*.jsonl` glob nor any merge prefix (so inert), but accumulate across resumed/re-run invocations. Inconsistent with arjun.go:105,109 which uses `defer os.Remove`.
**Fix:** `defer os.Remove(...)` immediately after each temp file is created, mirroring arjun/jsluice.

### WR-04: `mantra` discards the tool exit error — cannot distinguish "no secrets" from "crashed/timed-out"

**File:** `internal/modules/web/mantra.go:118-124`
**Issue:** `runErr := cmd.Run()` is captured into `execErr` then discarded (`_ = execErr`) on the premise that mantra exits non-zero when no secrets are found. This also swallows real failures: missing shared lib, panic, OOM-kill, or `context.DeadlineExceeded` from the 300s timeout all look identical to "0 secrets", and the task returns `StatusDone` with `secrets_found: 0`. Given XCUT-07's emphasis on not missing secrets, an unobserved mantra crash silently drops all JS-secret coverage. Same assumption in nomore403.go:113-119 and gxss.go:103-108.
**Fix:** Inspect the error: treat `*exec.ExitError` as benign only when stdout was produced (or the code matches the documented "no findings" code); surface `cmdCtx.Err() == context.DeadlineExceeded` and exec-not-found at `Warn`.

### WR-05: `extractHostFromURL` drops scheme-less authorities, yielding empty `host` on finding records

**File:** `internal/modules/web/urldedup.go:266-289` (reused by nomore403.go:170, gxss.go:179, arjun.go:204)
**Issue:** `extractHostFromURL` requires `"://"` and returns `""` when absent (lines 271-274). URL producers scope-filter via `extract/urls.ExtractURLs` (schemed output), so urldedup impact is low. But the same function sets `FindingRecord.Host` for nomore403/Gxss/arjun, whose tool output lines are not guaranteed schemed (e.g. `example.com/path 200`). Those findings then carry empty `host`, weakening the SARIF records.
**Fix:** Accept scheme-less authorities (parse first whitespace token, strip path/query, then port) or fall back to `url.Parse` so plain-text tool findings retain their host.

## Info

### IN-01: `hakoriginfinder.go` carries dead helpers `readIPsFromJSONL` and `readHostnamesFromJSONL`

**File:** `internal/modules/web/hakoriginfinder.go:240-313`
**Issue:** After the CR-06 per-host rewrite, `Run` uses only `readHostIPPairsFromJSONL`. `readIPsFromJSONL` (244-276) and `readHostnamesFromJSONL` (281-313) are unreferenced by production code. Dead code invites drift.
**Fix:** Delete both, or move to `_test.go` if used by tests. Cross-check the structural-findings substrate before removing.

### IN-02: `parseHakoriginOutput` accepts invalid IPv4 (e.g. `999.999.999.999`)

**File:** `internal/modules/web/hakoriginfinder.go:190-199` (and test hakoriginfinder_test.go:177)
**Issue:** The regex matches octets up to 999; the test explicitly encodes `999.999.999.999` as acceptable ("validation is caller's concern"), but no caller validates, so an out-of-range string can land in `OriginRecord.OriginIP`. Cosmetic given origin confidence is "low".
**Fix:** Add an octet `<= 255` check (or `net.ParseIP`) before accepting the match.

### IN-03: `TestJSAUsesDirectExec` asserts almost nothing about the behavior it names

**File:** `internal/modules/web/hakoriginfinder_test.go:128-161`
**Issue:** The name promises verification that jsa uses direct `exec.CommandContext` not the registry, but the body only checks `Name() == "web.jsa"` and non-empty `Description()`, plus log lines. It never invokes `JsaTask.Run`, never asserts skip-on-missing-binary, never inspects the exec mechanism. It would pass even if jsa were reverted to registry-based invocation — a tautological test inflating apparent coverage.
**Fix:** Either drive `JsaTask.Run` with a config pointing at a non-existent tools dir and assert `StatusSkipped`, or delete it (the real "no registry import" guarantee is already covered by the FOUND-10 allowlist test).

### IN-04: Two divergent `normalizeHost` implementations (port/IPv6 handling differs)

**File:** `internal/modules/web/nuclei.go:379-386` vs `internal/extract/waf/waf.go:131-145`
**Issue:** nuclei's `normalizeHost` strips scheme+path but NOT the port; waf's strips scheme+path+port with an IPv6 guard. nuclei uses its version to key the WAF-host set (`readWAFHostsSet` nuclei.go:355-376) and match `allHosts` (nuclei.go:169). If `waf.jsonl` hosts ever carried explicit ports, the two would disagree and WAF rate-halving would mis-classify. Latent coupling, not a present bug (waf records are port-free today).
**Fix:** Consolidate on a single shared `normalizeHost`, or document why nuclei retains the port. Low priority.

---

_Reviewed: 2026-06-03T09:40:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_

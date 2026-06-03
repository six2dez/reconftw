// Package web implements reconFTW v2's web analysis pipeline.
//
// JSONL STAGING CONTRACT (mirrors internal/modules/subdomains/doc.go — D-W2):
//
// Tasks writing MULTI-WRITER artefacts (urls / findings / waf) MUST NOT call
// app.Tree.Append directly. Each task writes a unique per-task staging file:
//
//	inputs/urls.<toolName>.jsonl      — katana, urlfinder, waymore, subjs, jsluice, jsa, mantra
//	inputs/findings.<toolName>.jsonl  — nuclei, arjun, gxss, nomore403, shortscan
//	inputs/waf.<toolName>.jsonl       — wafw00f, cdncheck
//
// For findings/waf: MergeStage / MergeAllWebArtefacts (merge.go) is the SINGLE
// app.Tree.Append caller — it globs inputs/<artefact>.*.jsonl, deduplicates by raw
// JSON line bytes, and calls Append once.
//
// For urls: urldedup is the SINGLE semantic-dedup Append caller for urls. It globs
// ALL inputs/urls.*.jsonl (fetch-stage producers: katana/urlfinder/waymore AND
// js-analyze producers: subjs/jsluice/jsa/mantra) after the full js-analyze stage
// completes, runs urless/p1radup semantic dedup over the full union, then calls
// app.Tree.Append once. This makes urldedup the authoritative single-writer for
// artefacts/urls.jsonl (WEB-14).
//
// Single-writer artefacts (hosts / origins / vhosts / favicons / csprecon_hosts /
// fuzz / js_secrets) KEEP calling app.Tree.Append directly — they have exactly one
// producer task and no REPLACE-semantics data-loss risk.
//
// jsa fan-out guarantee: jsa.go goroutines accumulate results in a mutex-protected
// allRecords slice; output.WriteJSONL is called ONCE after wg.Wait() — no concurrent
// writes to inputs/urls.jsa.jsonl.
//
// STAGING CONTRACT (mirrors internal/modules/subdomains — D-W2):
//
// Each Tool has its own Task file (httpx.go, nuclei.go, ffuf.go, …).
// Tasks self-register via init() calls in their respective files.
// Blank-import this package in cmd/reconftw/modules.go to trigger registration.
//
// FAILURE POLICY (D-W12, ADR §7):
//
// The entire web module group is best_effort. httpx is the DAG dependency root
// (DependsOn returns nil for HTTPXTask); all other Tasks return []string{"web.httpx"}
// or a downstream task name via DependsOn. An empty httpx output means every
// downstream Task runs with empty input and the run completes with warnings —
// NO fail_fast gate anywhere in the web pipeline.
//
// INPUT BOUNDARY (D-W10):
//
// HTTPXTask.Run resolves its host input in this precedence order:
//  1. --hosts FILE flag (via app.ExtraFlags["hosts"] or app.Target.WorkDir + ctx value)
//  2. artefacts/hosts.jsonl (prior web run)
//  3. artefacts/subdomains.jsonl (prior subs run, hostnames only)
//  4. fail-fast with actionable error message
//
// ARTEFACT SCHEMAS (D-W11 — planner may ADD fields, not remove):
//
//   - hosts.jsonl: {host, url, scheme, port, status, title, tech[], content_length, ip, cdn}
//   - fuzz.jsonl: {url, status, length, words, lines, redirect}
//   - waf.jsonl: {host, waf, cdn, detected_by}
//   - origins.jsonl: {host, origin_ip, method, confidence}
//   - URL records: {url, source, host}
//   - JS-secret records: {url, type, secret_redacted, severity}
//   - findings.jsonl: SARIF-compatible shape from Phase 4
//
// All Task files import:
//   - internal/core/appctx for AppContext
//   - internal/core/task for Result/Status/Register
//   - internal/core/config for Enabled() gating
package web

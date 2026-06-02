// Package web implements reconFTW v2's web analysis pipeline.
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

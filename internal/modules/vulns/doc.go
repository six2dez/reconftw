// Package vulns implements reconFTW v2's vulnerability scanning pipeline.
//
// JSONL STAGING CONTRACT (mirrors internal/modules/web/doc.go — D-V1/D-W2):
//
// Tasks writing the shared findings artefact MUST NOT call app.Tree.Append
// directly. Each task writes a unique per-task staging file:
//
//	inputs/findings.<toolName>.jsonl  — dalfox, sqlmap, ghauri, crlfuzz, commix,
//	                                    smugglex, TInjA, SSTImap, interactsh,
//	                                    WCVS, toxicache, second-order,
//	                                    nuclei-dast, fray, testssl, bypass4xx
//
// MergeVulnsFindings / MergeAllVulnsArtefacts (merge.go) is the SINGLE
// app.Tree.Append caller — it globs inputs/findings.*.jsonl, deduplicates
// by raw JSON line bytes, and calls Append once. This prevents the
// REPLACE-semantics data-loss that Phase 4 B2 fixed.
//
// gf bucket files (inputs/gf/<class>.txt) are single-writer artefacts written
// directly by GFTask — they do NOT go through the staging+merge pipeline.
// Each scanner Task reads its own bucket (DependsOn "vulns.gf").
//
// STAGING CONTRACT:
//
// Each Tool has its own Task file (gf.go, dalfox.go, sqlmap.go, …).
// Tasks self-register via init() calls in their respective files.
// Blank-import this package in cmd/reconftw/modules.go to trigger registration.
//
// FAILURE POLICY (D-V7, ADR §7 line 49):
//
// The entire vulns module group is best_effort. GFTask is the DAG dependency
// root (DependsOn returns nil); all scanner Tasks return []string{"vulns.gf"}
// or a downstream task name via DependsOn. An empty gf bucket means the
// downstream scanner runs with empty input → empty output → run COMPLETES.
// No fail_fast gate anywhere in the vulns pipeline.
//
// INPUT BOUNDARY (D-V5):
//
// GFTask.Run resolves its URL input in this precedence order:
//  1. app.ExtraFlags["urls"] — --urls FILE flag (set by runVulnsCmd)
//  2. artefacts/urls.jsonl (prior web run output)
//  3. fail-fast with actionable error: "no URL corpus — run `web` first or pass `--urls`"
//
// No hidden bootstrap — vulns never silently triggers the web pipeline.
// This keeps the seeded-local E2E feasible (D-V9) and respects the dev-Mac
// DNS block (memory/project_local_dns_block).
//
// ARTEFACT SCHEMAS (Claude's Discretion — extend Phase 4/5 shape, never remove):
//
//   - inputs/gf/<class>.txt:  one URL per line, per gf pattern class
//   - inputs/findings.<tool>.jsonl: VulnFindingRecord (SARIF-compatible + vuln fields)
//   - artefacts/findings.jsonl: merged+deduped union (MergeAllVulnsArtefacts)
//
// VulnFindingRecord extends the Phase 4/5 findings.jsonl SARIF-compatible shape:
//
//	{
//	  // Phase 4/5 inherited fields (SARIF-compatible):
//	  "severity":   "high|medium|low|info|critical",
//	  "confidence": "confirmed|high|medium|low",
//	  "references": ["https://..."],
//	  // Phase 6 additions (omitempty — absent = not applicable):
//	  "vuln_class":        "xss|sqli|ssrf|lfi|rce|ssti|crlf|cmdi|smuggling|...",
//	  "matched_param":     "param name that triggered the finding",
//	  "payload_redacted":  "payload with secret/canary values stripped (XCUT-07)",
//	  "poc_redacted":      "PoC URL/request with secret values stripped (XCUT-07)",
//	  "engine":            "dalfox|sqlmap|ghauri|commix|..."
//	}
//
// PAYLOAD REDACTION (XCUT-07):
//
// All secret and payload values MUST be redacted before write. Tasks MUST NOT
// write raw tool stderr/stdout containing live payloads to artefacts. Use
// app.Log redactor (Layer 1) and field-level stripping (Layer 2) before
// marshalling VulnFindingRecord.
//
// All Task files import:
//   - internal/core/appctx for AppContext
//   - internal/core/task for Result/Status/Register
//   - internal/core/config for Enabled() gating
package vulns

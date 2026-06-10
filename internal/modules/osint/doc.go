// Package osint implements reconFTW v2's OSINT collection pipeline.
//
// JSONL STAGING CONTRACT (mirrors internal/modules/vulns/doc.go — D-O3/D-O5):
//
// Tasks writing the shared findings artefact MUST NOT call app.Tree.Append
// directly. Each task writes a unique per-task staging file:
//
//	inputs/findings.<toolName>.jsonl  — domain_info, ip_info, emails,
//	                                    github_dorks, gitdorks, github_repos,
//	                                    github_leaks, github_actions, cloud_enum,
//	                                    postman, swagger, spoofy, msftrecon,
//	                                    cmseek, favirecon, gqlspection, cewler,
//	                                    xnldorker, metadata, misconfig
//
// MergeOSINTFindings / MergeAllOSINTArtefacts (merge.go) is the SINGLE
// app.Tree.Append caller — it globs inputs/findings.*.jsonl, deduplicates
// by raw JSON line bytes, and calls Append once. This prevents the
// REPLACE-semantics data-loss that Phase 4 B2 fixed.
//
// D-O5 osint/*.txt SINGLE-WRITER ARTEFACTS:
//
// High-value v1 human-facing files (osint/emails.txt, osint/ip_*_whois.txt,
// osint/azure_tenant_domains.txt, …) are written directly with os.WriteFile to
// the osint/ subdir. They are SINGLE-WRITER artefacts (like vulns gf buckets)
// and do NOT go through the staging+merge pipeline. NOTE: OutputTree.Append
// only scope-checks findings/subdomains/hosts/urls artefacts (tree.go); the
// osint/*.txt files are written outside the Tree, so they bypass scope dispatch
// by design.
//
// STAGING CONTRACT:
//
// Each tool has its own Task file (domain_info.go, ip_info.go, …).
// Tasks self-register via init() calls in their respective files.
// Blank-import this package in cmd/reconftw/modules.go to trigger registration.
//
// FAILURE POLICY (D-O8, ARCH-09, ADR §7):
//
// The entire osint module group is best_effort — there is NO fail_fast gate
// anywhere in the osint pipeline. A tool failing, finding nothing, or being
// gated out by a missing API key logs a warning and the run COMPLETES. This
// deliberately differs from vulns (no single DAG root): most OSINT Tasks are
// root-domain-seeded and return nil from DependsOn (the scheduler semaphore
// parallelizes them, mirroring v1's 4 parallel osint groups).
//
// INPUT BOUNDARY (D-O1 / D-O2):
//
// OSINT is root-domain / company-seeded — NOT URL-corpus-seeded. `reconftw
// osint --target example.com` runs entirely from the root domain + derived
// company name (unfurl format %r analog). It has NO hard dependency on prior
// subs/web runs and NEVER triggers them (no silent bootstrap, mirrors D-V5).
//
// The ~2 enrichment functions that benefit from subdomain/web context
// (metadata = exiftool over downloaded indexed docs; apileaks over discovered
// hosts) consume workspace subs/web artefacts IF they already exist, but
// log-skip the enrichment when absent and the run completes (ARCH-09
// best_effort + logged-never-silent). Pure opportunistic enrichment over the
// root-domain baseline — no fail, no bootstrap, no coupling.
//
// ARTEFACT SCHEMAS (Claude's Discretion — D-O4, may ADD fields, never remove):
//
//   - inputs/findings.<tool>.jsonl: OSINTFindingRecord (SARIF-compatible + osint fields)
//   - artefacts/findings.jsonl: merged+deduped union (MergeAllOSINTArtefacts)
//   - osint/*.txt: single-writer human-facing files (D-O5)
//
// OSINTFindingRecord extends the Phase 4/5/6 findings.jsonl SARIF-compatible
// shape with an "informational" severity (D-O4 — the ONLY findings-schema enum
// extension) plus osint-specific fields (class, source, category,
// value_redacted, poc_redacted). See record.go.
//
// SECRET REDACTION (XCUT-07 — THE critical XCUT for this phase):
//
// OSINT's github_leaks/trufflehog/apileaks/Postman/Swagger sources emit ACTUAL
// live credentials. All secret values MUST be redacted before any log or
// artefact write. Tasks MUST NOT write raw tool stdout/stderr containing live
// secrets to artefacts. Use app.Log redactor (Layer 1, register the value) and
// field-level stripping (Layer 2, OSINTFindingRecord.ValueRedacted /
// PoCRedacted) before marshalling. Log ONLY counts, never raw matches.
//
// All Task files import:
//   - internal/core/appctx for AppContext
//   - internal/core/task for Result/Status/Register
//   - internal/core/config for Enabled() gating
package osint

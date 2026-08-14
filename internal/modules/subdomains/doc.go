package subdomains

// Package subdomains implements reconFTW v2's subdomain enumeration pipeline.
//
// STAGING CONTRACT (addresses REVIEWS finding #2 + #3 — OutputTree.Append=REPLACE):
// Tasks do NOT call app.Tree.Append("subdomains", ...) directly during Run.
// Instead, each Task writes its raw output (one hostname per line) to a private
// staging file at:   workspaces/<target>/inputs/passive.<tool>.txt
//                    workspaces/<target>/inputs/resolved.<tool>.txt
//                    workspaces/<target>/inputs/brute.<tool>.txt
// The command layer (newSubsCmd in cmd/reconftw/stub_subcommands.go) calls
// MergeStage(app, stageName) after each RunStage call returns. MergeStage:
//   1. Reads all inputs/<stage>.*.txt files
//   2. Deduplicates (anew-equivalent, case-insensitive, sorted)
//   3. Converts each hostname to SubdomainRecord{subdomain, source="merged", first_seen}
//   4. Calls app.Tree.Append("subdomains", records) ONCE as the single writer
// This ensures REPLACE semantics are safe (one writer per artefact per stage).
//
// CONFIG NOTE — SubGeoTask.Enabled (W5):
// SubGeoTask.Enabled returns cfg.Subdomains.Enabled (the parent flag). There is NO
// separate geo flag in v1 and NO cfg.Subdomains.Geo struct exists or should be added.
// Executors MUST NOT invent a cfg.Subdomains.Geo field. Geo always runs when the
// subdomains module is enabled.
//
// FINDINGS STAGING CONTRACT (B2):
// TakeoverSubzyTask and TakeoverDNSTakeTask do NOT call app.Tree.Append("findings", ...)
// directly during Run. Each writes its own staging file:
//   inputs/takeover.subzy.jsonl and inputs/takeover.dnstake.jsonl
// The command layer reads both files after the enrichment RunStage completes and
// consolidates them into a THIRD staging file, inputs/findings.takeover.jsonl —
// it does NOT write the artefact directly. The single-writer-per-artefact
// invariant holds only within one RunStage, and composite modes run a later
// web.MergeStage("findings") whose REPLACE semantics erased anything written to
// the artefact earlier. Routing through staging keeps artefacts/findings.jsonl a
// pure function of inputs/findings.*.jsonl, so every later merge reproduces the
// takeover records instead of dropping them.
// Similarly: buckets, asns, hosts artefacts each have exactly ONE writer per RunStage.
//
// All Tasks in this package self-register via init() calls. Blank-import
// this package in cmd/reconftw/modules.go to trigger registration.

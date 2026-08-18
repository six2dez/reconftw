// staging.go — the vulns package's half of the F3 run-isolation contract.
//
// Every vuln scanner used to write its staging file only when it had data:
//
//	if len(findings) > 0 { … output.WriteJSONL(inputs/findings.<tool>.jsonl, lines) }
//
// so a run that observed NOTHING left the previous run's staging file on disk
// and MergeVulnsFindings republished it. A REMEDIATED VULNERABILITY reappeared
// in the report, SARIF, store and notifications of every later run as though
// this run had confirmed it — the finding-level expression of audit finding F3.
//
// stageVulnFindings replaces that shape. It is deliberately the ONLY staging
// entry point in this package so the write-or-remove decision lives in one
// place, and it takes `ran` as an EXPLICIT argument so every caller has to
// state which of the two cases it is in:
//
//	ran == true  — the scanner was dispatched this invocation and reached its
//	               result-collection point. Zero results is a real observation:
//	               the staging file is REMOVED so the merge cannot republish a
//	               previous run's findings.
//	ran == false — the scanner never ran (its binary is absent, every dispatch
//	               failed, the run was cancelled before any tool started). It
//	               observed nothing, so it may not delete what a previous run
//	               did observe. The staging file is left alone.
//
// The `ran == false` half is not defensive padding: without it this migration
// would CONVERT a staleness bug into a data-loss bug on any host that has not
// installed an optional scanner — the same call made for web/jsluice.go in
// plan 15-13.
//
// WHAT DOES NOT BELONG HERE. Three other kinds of file live under inputs/ and
// must keep their raw unconditional writes (see internal/core/output/staging.go
// and the header of internal/modules/staging_contract_test.go):
//
//   - TOOL-INPUT files handed to an external binary — inputs/tmp_sqli.txt (-m
//     for sqlmap), inputs/tmp_rce.txt (-m for commix), inputs/xss_reflected.txt,
//     inputs/crlfuzz_hosts.txt, … Sixteen of them live in the SAME function as
//     a genuine staging write. Remove-on-empty would change the contract of a
//     file passed on argv.
//   - DERIVED intermediates under an inputs/ SUBDIRECTORY — inputs/gf/<class>.txt.
//     Four scanners stat those buckets; gf.go rewrites every one of them on
//     every run and writes an EMPTY bucket rather than removing it.
//   - Raw tool output that this package parses (inputs/nuclei_dast_raw.jsonl,
//     inputs/fuzzparams_raw.jsonl, …). Those are scanner-native schemas, not
//     staging records.
//
// Source: .planning/phases/15-release-gates-run-isolation-store-integrity/15-14-PLAN.md
package vulns

import (
	"encoding/json"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/output"
)

// stageVulnFindings publishes findings to stagingPath under the F3
// write-or-remove contract, or preserves the file when the scanner never ran.
//
// taskName is the dot-namespaced task identifier ("vulns.sqli") and is used
// only for log attribution — never the staging file name, which callers pass
// verbatim so a rename can never silently drop a producer from the
// inputs/findings.*.jsonl merge glob.
//
// Errors are logged at Debug and swallowed: the vulns module is
// PolicyBestEffort and a staging write failure must not abort the pipeline.
func stageVulnFindings(app *appctx.AppContext, taskName, stagingPath string,
	ran bool, findings []VulnFindingRecord,
) {
	if !ran {
		// The scanner did not observe the corpus, so it has no standing to
		// delete what a previous run observed. Preserve, and say so.
		if app != nil && app.Log != nil {
			app.Log.Debug(taskName+": scanner did not run — staging preserved (F3 did-not-run)",
				"path", stagingPath)
		}
		return
	}
	var lines [][]byte
	for _, rec := range findings {
		b, mErr := json.Marshal(rec)
		if mErr != nil {
			continue
		}
		lines = append(lines, b)
	}
	if wErr := output.StageJSONL(stagingPath, lines); wErr != nil && app != nil && app.Log != nil {
		app.Log.Debug(taskName+": staging write failed", "path", stagingPath, "err", wErr)
	}
}

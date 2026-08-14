// e2e_findings_test.go — end-to-end gate for the findings pipeline:
//
//	producer record type → staging write → merge → scope gate → artefacts/findings.jsonl
//
// # WHY THIS EXISTS
//
// The unit tests in internal/core/output/tree_test.go prove the scope gate
// works, but they feed it hand-written JSON that already carries a "host"
// field. That fixture encodes the very assumption under test, so it can never
// detect that the REAL producers emit records with no locator at all. This
// test closes that blind spot by using production types and the production
// write path — no hand-written JSON, no fabricated fixtures.
//
// It is named TestE2E* so the CI integration gate selects it. The gate asserts
// a non-zero match count, because `go test -run` exits 0 when its pattern
// matches nothing — which is how the previous kernel-demo gate stayed green
// for months while running no tests at all.
package vulns_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/modules/vulns"
)

// newFindingsWorkspace builds a real OutputTree with a real scope filter,
// mirroring what appctx.Boot wires up for a live scan.
func newFindingsWorkspace(t *testing.T) (*appctx.AppContext, string) {
	t.Helper()
	workDir := t.TempDir()
	tree, err := output.NewTree(workDir, &output.DefaultScopeFilter{
		Patterns: []string{"example.com", "*.example.com"},
	})
	if err != nil {
		t.Fatalf("output.NewTree: %v", err)
	}
	return &appctx.AppContext{
		Tree:   tree,
		Target: &appctx.Target{WorkDir: workDir},
	}, workDir
}

// stageRecords marshals records and writes them through the SAME helper the
// producers use (output.WriteJSONL), so the test exercises the production
// staging path rather than a hand-rolled imitation.
func stageRecords(t *testing.T, workDir, filename string, recs ...any) {
	t.Helper()
	var lines [][]byte
	for _, r := range recs {
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatalf("marshal staging record: %v", err)
		}
		lines = append(lines, b)
	}
	path := filepath.Join(workDir, "inputs", filename)
	if err := output.WriteJSONL(path, lines); err != nil {
		t.Fatalf("output.WriteJSONL(%s): %v", filename, err)
	}
}

// TestE2EVulnFindingReachesArtefacts is the core contract: a vulnerability
// found by a scanner must survive the merge and land in artefacts/findings.jsonl.
//
// The record is built with the exported production type exactly as
// vulns/sqli.go does — if that type cannot carry a locator through the scope
// gate, this test fails, which is the entire point.
func TestE2EVulnFindingReachesArtefacts(t *testing.T) {
	app, workDir := newFindingsWorkspace(t)

	// Exactly what sqli.go constructs for a confirmed injection.
	stageRecords(t, workDir, "findings.sqli.jsonl", vulns.VulnFindingRecord{
		Host:            "api.example.com",
		Severity:        "critical",
		Confidence:      "high",
		VulnClass:       "sqli",
		PayloadRedacted: "***",
		PoCRedacted:     "***",
		Engine:          "sqlmap",
	})

	if err := vulns.MergeVulnsFindings(context.Background(), app, "findings"); err != nil {
		t.Fatalf("MergeVulnsFindings: a confirmed critical finding was rejected: %v", err)
	}

	body, err := os.ReadFile(filepath.Join(workDir, "artefacts", "findings.jsonl"))
	if err != nil {
		t.Fatalf("artefacts/findings.jsonl was never written — the finding was lost: %v", err)
	}
	if !bytes.Contains(body, []byte(`"vuln_class":"sqli"`)) {
		t.Errorf("sqli finding missing from artefacts/findings.jsonl; got: %s", body)
	}
}

// TestE2EFindingsBatchNotPoisonedByOneRecord guards the amplification failure
// mode. MergeVulnsFindings makes ONE Tree.Append call over every staging file,
// and Append is all-or-nothing by design — so a single unusable record must not
// be allowed to destroy well-formed, in-scope findings from other scanners.
//
// This is the same failure shape as the web.urldedup URL data-loss P0: an
// aggregator handing unfiltered input to a strict boundary.
func TestE2EFindingsBatchNotPoisonedByOneRecord(t *testing.T) {
	app, workDir := newFindingsWorkspace(t)

	// A well-formed, in-scope finding from a scanner that carries a locator
	// (websocket/grpc/testssl all produce this shape).
	stageRecords(t, workDir, "findings.websocket.jsonl", map[string]any{
		"host":       "api.example.com",
		"severity":   "high",
		"vuln_class": "websocket",
		"engine":     "smugglex",
	})

	// One locator-less record from a VulnFindingRecord producer.
	stageRecords(t, workDir, "findings.sqli.jsonl", vulns.VulnFindingRecord{
		Severity:  "critical",
		VulnClass: "sqli",
		Engine:    "sqlmap",
	})

	_ = vulns.MergeVulnsFindings(context.Background(), app, "findings")

	body, err := os.ReadFile(filepath.Join(workDir, "artefacts", "findings.jsonl"))
	if err != nil {
		t.Fatalf("one bad record destroyed the whole batch — the well-formed "+
			"in-scope websocket finding never reached artefacts: %v", err)
	}
	if !bytes.Contains(body, []byte(`"vuln_class":"websocket"`)) {
		t.Errorf("well-formed finding lost from batch; got: %s", body)
	}
}

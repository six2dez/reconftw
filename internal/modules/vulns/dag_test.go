// dag_test.go — Vulns task-DAG build + topological-order regression guard.
//
// These tests close the structural gap mirroring web/dag_test.go (Phase 5
// CR-01/CR-02/CR-03 lesson): the multi-writer staging tests call
// MergeVulnsFindings directly and NEVER build the DAG, so a circular
// DependsOn could pass `go build` and the whole unit suite while the
// `vulns` subcommand aborted before any task ran.
//
// TestVulnsDAGBuilds asserts task.Default.Build() returns NO error — the
// registered vulns (+ subdomains + web, via the cross-package singleton) task
// graph is acyclic and dependency-complete.
//
// TestVulnsDAGTopoOrder asserts the topological order places vulns.gf BEFORE
// every scanner Task that DependsOn it. This catches a reintroduced backwards
// edge AND a stage/DependsOn contradiction (mirrors Phase 5 CR-02).
//
// Source: .planning/phases/06-vulnerability-scanning-e2e/06-09-PLAN.md Task 1.
package vulns_test

import (
	"testing"

	"github.com/six2dez/reconftw/internal/core/task"

	// Blank import triggers init() Task registrations for every vulns Task.
	_ "github.com/six2dez/reconftw/internal/modules/vulns"
)

// TestVulnsDAGBuilds is the cheapest durable guard against a DependsOn cycle
// or missing-dependency reference landing undetected (it would otherwise only
// fail when a human runs `reconftw vulns`). Build() runs the same topological
// sort + cycle detection that runVulnsCmd relies on at startup.
func TestVulnsDAGBuilds(t *testing.T) {
	if _, err := task.Default.Build(); err != nil {
		t.Fatalf("vulns task DAG does not build (cycle / missing dependency): %v\n"+
			"This is the CR-01 failure mode: `reconftw vulns` aborts before any task runs.", err)
	}
}

// TestVulnsDAGTopoOrder verifies that vulns.gf (the DAG root, D-V4) topo-sorts
// BEFORE every scanner Task that DependsOn it. This is the structural contract
// that keeps the whole pipeline from deadlocking at runtime.
func TestVulnsDAGTopoOrder(t *testing.T) {
	ordered, err := task.Default.Build()
	if err != nil {
		t.Fatalf("Build() returned error (cycle?): %v", err)
	}

	// Map each task name to its position in the topological order.
	pos := make(map[string]int, len(ordered))
	for i, tk := range ordered {
		pos[tk.Name()] = i
	}

	gfIdx, ok := pos["vulns.gf"]
	if !ok {
		t.Fatal("vulns.gf not present in built DAG — registration regression")
	}

	// Every scanner Task that DependsOn "vulns.gf" must topo-sort AFTER the
	// gf root. All 19 scanner tasks registered by the vulns package are listed
	// here. A missing name is flagged as a registration regression; a wrong
	// ordering is flagged as a DependsOn/stage contradiction.
	scanners := []string{
		"vulns.xss",
		"vulns.sqli",
		"vulns.crlf",
		"vulns.lfi",
		"vulns.ssti",
		"vulns.ssrf",
		"vulns.cmdi",
		"vulns.smuggling",
		"vulns.webcache_wcvs",
		"vulns.second_order",
		"vulns.nuclei_dast",
		"vulns.fuzzparams",
		"vulns.bypass4xx",
		"vulns.testssl",
		"vulns.fray",
		"vulns.graphql",
		"vulns.grpc",
		"vulns.llm",
		"vulns.websocket",
	}

	for _, name := range scanners {
		idx, present := pos[name]
		if !present {
			t.Errorf("scanner %s not present in built DAG — registration regression", name)
			continue
		}
		if idx <= gfIdx {
			t.Errorf("topo order: %s (idx %d) must follow vulns.gf (idx %d) — "+
				"scanner DependsOn gf to read its gf bucket input", name, idx, gfIdx)
		}
	}
}

// dag_test.go — OSINT task-DAG build + all-tasks-present regression guard.
//
// These tests close the structural gap mirroring vulns/dag_test.go +
// web/dag_test.go (Phase 5 CR-01 / Phase 6 lesson): the multi-writer staging
// and parity tests exercise parse/merge helpers directly and NEVER build the
// DAG, so a circular DependsOn (or a Task that silently failed to register)
// could pass `go build` and the whole unit suite while the `osint` subcommand
// aborted before any task ran. This is the CR-01 failure mode.
//
// TestOSINTDAGBuilds asserts task.Default.Build() returns NO error — the
// registered task graph (osint + any cross-package singletons) is acyclic and
// dependency-complete.
//
// TestOSINTDAGContainsAllTasks asserts every registered osint.* Task name is
// PRESENT in the built DAG (registration regression guard). Unlike vulns (which
// has a single gf root), OSINT has NO single root — most Tasks have nil
// DependsOn (D-O1, root-domain seeded). The only real edge is
// osint.github_leaks DependsOn osint.github_repos (D-O10 fold: the enumerated
// repo list feeds the per-repo trufflehog scan), which this test also asserts.
//
// Source: .planning/phases/07-osint-e2e/07-06-PLAN.md Task 1.
package osint_test

import (
	"testing"

	"github.com/six2dez/reconftw/internal/core/task"

	// Blank import triggers init() Task registrations for every osint Task.
	_ "github.com/six2dez/reconftw/internal/modules/osint"
)

// allOSINTTaskNames lists every Task the osint package registers via init().
// A missing name in the built DAG is a registration regression; the list is
// the authoritative coverage contract (20 Tasks, matching 07-06-PLAN.md Task 1).
var allOSINTTaskNames = []string{
	"osint.domain_info",
	"osint.ip_info",
	"osint.emails",
	"osint.spoofy",
	"osint.github_dorks",
	"osint.gitdorks",
	"osint.github_repos",
	"osint.github_leaks",
	"osint.github_actions",
	"osint.cloud_enum",
	"osint.postman",
	"osint.swagger",
	"osint.misconfig",
	"osint.msftrecon",
	"osint.cmseek",
	"osint.favirecon",
	"osint.gqlspection",
	"osint.cewler",
	"osint.xnldorker",
	"osint.metadata",
}

// TestOSINTDAGBuilds is the cheapest durable guard against a DependsOn cycle or
// missing-dependency reference landing undetected (it would otherwise only fail
// when a human runs `reconftw osint`). Build() runs the same topological sort +
// cycle detection that runOSINTCmd relies on at startup.
func TestOSINTDAGBuilds(t *testing.T) {
	if _, err := task.Default.Build(); err != nil {
		t.Fatalf("osint task DAG does not build (cycle / missing dependency): %v\n"+
			"This is the CR-01 failure mode: `reconftw osint` aborts before any task runs.", err)
	}
}

// TestOSINTDAGContainsAllTasks verifies every registered osint.* Task is present
// in the built DAG (registration regression guard — closes CR-01 where the
// merge/parity tests never built the DAG) and asserts the one real edge:
// osint.github_leaks topo-sorts AFTER osint.github_repos.
func TestOSINTDAGContainsAllTasks(t *testing.T) {
	ordered, err := task.Default.Build()
	if err != nil {
		t.Fatalf("Build() returned error (cycle?): %v", err)
	}

	// Map each task name to its position in the topological order.
	pos := make(map[string]int, len(ordered))
	for i, tk := range ordered {
		pos[tk.Name()] = i
	}

	for _, name := range allOSINTTaskNames {
		if _, present := pos[name]; !present {
			t.Errorf("osint Task %q not present in built DAG — registration regression "+
				"(missing init() task.Register, or the Task was dropped)", name)
		}
	}

	// The single real DAG edge (D-O10 fold): github_leaks reads the repo list
	// produced by github_repos, so it MUST topo-sort AFTER it. A reversed or
	// dropped edge deadlocks the pipeline at runtime.
	reposIdx, reposOK := pos["osint.github_repos"]
	leaksIdx, leaksOK := pos["osint.github_leaks"]
	switch {
	case !reposOK:
		t.Error("osint.github_repos not present in built DAG — registration regression")
	case !leaksOK:
		t.Error("osint.github_leaks not present in built DAG — registration regression")
	case leaksIdx <= reposIdx:
		t.Errorf("topo order: osint.github_leaks (idx %d) must follow osint.github_repos (idx %d) — "+
			"github_leaks DependsOn github_repos to read its enumerated repo list (D-O10)",
			leaksIdx, reposIdx)
	}
}

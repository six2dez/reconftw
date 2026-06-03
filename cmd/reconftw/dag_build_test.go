// dag_build_test.go — Cross-phase task-DAG build gate (WR-01, 05-REVIEW).
//
// runWebCmd / runSubsCmd assemble the full task graph only at runtime via
// task.Default.Build(); there was no build-time assertion that the registered
// Task set is acyclic and dependency-complete. CR-01 proved a DependsOn cycle
// can land, pass `go build` and the entire unit suite, and only fail when a
// human runs the subcommand.
//
// This test blank-imports the same module packages as cmd/reconftw/modules.go
// (subdomains + web, via the package-main build) and calls task.Default.Build()
// — the exact path runWebCmd uses at stub_subcommands.go Step 8. It fails the
// build if any cross-phase DependsOn regression reintroduces a cycle or a
// dangling dependency, for every registered module, not just web.
//
// Source: .planning/phases/05-web-pipeline-e2e/05-REVIEW.md WR-01.
package main

import (
	"testing"

	"github.com/six2dez/reconftw/internal/core/task"
)

// TestRegisteredTaskDAGBuilds asserts the FULL process-singleton task registry
// (every module blank-imported by modules.go) topologically sorts without a
// cycle or missing-dependency error. This is the cheapest durable guard against
// DependsOn regressions across all phases.
func TestRegisteredTaskDAGBuilds(t *testing.T) {
	ordered, err := task.Default.Build()
	if err != nil {
		t.Fatalf("registered task DAG does not build: %v\n"+
			"A DependsOn cycle or dangling dependency would abort the affected "+
			"subcommand at startup (CR-01 failure mode).", err)
	}
	if len(ordered) == 0 {
		t.Fatal("Build() returned an empty task slice — modules.go imports regressed")
	}
}

// TestWebURLDedupOrderingInFullDAG re-asserts the web urldedup producer/consumer
// ordering against the FULL registry topo order (CR-02 guard at the cmd layer):
// every URL producer precedes web.urldedup, and its consumers follow it. A stage
// loop that runs gxss/arjun before urldedup contradicts this ordering.
func TestWebURLDedupOrderingInFullDAG(t *testing.T) {
	ordered, err := task.Default.Build()
	if err != nil {
		t.Fatalf("Build() returned error: %v", err)
	}
	pos := make(map[string]int, len(ordered))
	for i, tk := range ordered {
		pos[tk.Name()] = i
	}
	dedupIdx, ok := pos["web.urldedup"]
	if !ok {
		t.Skip("web.urldedup not registered in this build — skipping web-specific ordering check")
	}
	for _, name := range []string{
		"web.katana", "web.urlfinder", "web.waymore",
		"web.subjs", "web.jsluice", "web.jsa", "web.mantra",
	} {
		if idx, present := pos[name]; present && idx >= dedupIdx {
			t.Errorf("%s (idx %d) must precede web.urldedup (idx %d)", name, idx, dedupIdx)
		}
	}
	for _, name := range []string{"web.arjun", "web.gxss"} {
		if idx, present := pos[name]; present && idx <= dedupIdx {
			t.Errorf("%s (idx %d) must follow web.urldedup (idx %d)", name, idx, dedupIdx)
		}
	}
}

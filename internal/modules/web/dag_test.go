// dag_test.go — Web task-DAG build + topological-order regression guard.
//
// These tests close the structural gap behind CR-01/CR-02/CR-03 (05-REVIEW):
// the multi-writer staging tests (merge_multiwriter_test.go) call
// MergeAllWebArtefacts directly and NEVER build the DAG, so a circular
// DependsOn (web.urldedup -> web.subjs -> web.urldedup) passed `go build` and
// the whole unit suite while the `web` subcommand could not start.
//
// TestWebDAGBuilds asserts task.Default.Build() returns NO error — i.e. the
// registered web (+ subdomains, via the cross-package singleton) task graph is
// acyclic and dependency-complete. It FAILS against the pre-fix subjs backwards
// edge with the exact ConfigError runWebCmd would surface, and PASSES once subjs
// depends on its real upstream producers (katana/urlfinder/waymore).
//
// TestWebDAGTopoOrder asserts the topological order places web.urldedup AFTER
// every URL producer (katana/urlfinder/waymore/subjs/jsluice/jsa/mantra) and
// BEFORE its only legitimate consumers (web.arjun/web.gxss). This catches a
// reintroduced backwards edge AND a stage/DependsOn contradiction (CR-02).
//
// Source: .planning/phases/05-web-pipeline-e2e/05-REVIEW.md CR-03 / WR-01.
package web_test

import (
	"testing"

	"github.com/six2dez/reconftw/internal/core/task"

	// Blank import triggers init() Task registrations for every web Task.
	_ "github.com/six2dez/reconftw/internal/modules/web"
)

// TestWebDAGBuilds is the cheapest durable guard against a DependsOn cycle or a
// missing-dependency reference landing undetected (it would otherwise only fail
// when a human runs `reconftw web`). Build() runs the same topological sort +
// cycle detection that runWebCmd relies on at startup.
func TestWebDAGBuilds(t *testing.T) {
	if _, err := task.Default.Build(); err != nil {
		t.Fatalf("web task DAG does not build (cycle / missing dependency): %v\n"+
			"This is the CR-01 failure mode: `reconftw web` aborts before any task runs.", err)
	}
}

// TestWebDAGTopoOrder verifies the producer/consumer ordering around
// web.urldedup that the stage loop depends on.
func TestWebDAGTopoOrder(t *testing.T) {
	ordered, err := task.Default.Build()
	if err != nil {
		t.Fatalf("Build() returned error (cycle?): %v", err)
	}

	// Map each task name to its position in the topological order.
	pos := make(map[string]int, len(ordered))
	for i, tk := range ordered {
		pos[tk.Name()] = i
	}

	dedupIdx, ok := pos["web.urldedup"]
	if !ok {
		t.Fatal("web.urldedup not present in built DAG — registration regression")
	}

	// Every URL producer must topo-sort BEFORE urldedup (urldedup globs and
	// semantic-dedups ALL of their inputs/urls.*.jsonl staging files).
	producers := []string{
		"web.katana", "web.urlfinder", "web.waymore",
		"web.subjs", "web.jsluice", "web.jsa", "web.mantra",
	}
	for _, name := range producers {
		idx, present := pos[name]
		if !present {
			t.Errorf("URL producer %s not present in built DAG", name)
			continue
		}
		if idx >= dedupIdx {
			t.Errorf("topo order: %s (idx %d) must precede web.urldedup (idx %d) — "+
				"urldedup consumes its staging output", name, idx, dedupIdx)
		}
	}

	// urldedup's only legitimate consumers must topo-sort AFTER it (they read
	// the FINAL deduped artefacts/urls.jsonl that urldedup writes).
	consumers := []string{"web.arjun", "web.gxss"}
	for _, name := range consumers {
		idx, present := pos[name]
		if !present {
			t.Errorf("urldedup consumer %s not present in built DAG", name)
			continue
		}
		if idx <= dedupIdx {
			t.Errorf("topo order: %s (idx %d) must follow web.urldedup (idx %d) — "+
				"it reads the final deduped urls.jsonl", name, idx, dedupIdx)
		}
	}
}

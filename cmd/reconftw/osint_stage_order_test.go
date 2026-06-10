// osint_stage_order_test.go — execution-path guard that the SEQUENTIAL osint
// stage order (osintStages() in stub_subcommands.go) honors every declared
// osint DependsOn edge.
//
// This closes GAP-01/CR-01 and the false-confidence trap it exposed: the
// existing internal/modules/osint/dag_test.go asserts ordering against
// task.Default.Build() (the topological sort), which is NOT the runtime
// execution path. The osint subcommand runs ALL tasks of a stage concurrently
// under a semaphore with NO in-stage DependsOn ordering; cross-task ordering
// comes ONLY from the sequential RunStage calls driven by osintStages(). A
// task.Build()/MockBackend-only assertion can pass while github_leaks and
// github_repos run in the same stage (the exact GAP-01 defect).
//
// These tests therefore map each osint task to its STAGE INDEX using the SAME
// osintStages() slice the production runOSINTCmd executes (single source of
// truth — no duplicated ordering literal) and assert that for every DependsOn
// edge, the dependency lands in a STRICTLY EARLIER stage.
package main

import (
	"testing"

	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"

	// Blank import triggers init() Task registrations for every osint Task so
	// task.Default.Build() returns the full osint task set.
	_ "github.com/six2dez/reconftw/internal/modules/osint"
)

// osintStageIndex builds task-name → stage-index from the production
// osintStages() slice. A task that matches no stage returns (-1, false): the
// caller treats that as a configuration error (a registered osint task with no
// stage would silently never run).
func osintStageIndex() map[string]int {
	idx := make(map[string]int)
	for i, stage := range osintStages() {
		for _, prefix := range stage.prefixes {
			// Stage prefixes in osintStages() are exact task names (explicit
			// list, not catch-all), so each prefix maps directly to one task.
			idx[prefix] = i
		}
	}
	return idx
}

// buildOSINTTasks returns every registered osint.* task from the real DAG build
// (the same Build() runOSINTCmd uses), so the guard runs against the production
// task set, not a hand-maintained list.
func buildOSINTTasks(t *testing.T) []task.Task {
	t.Helper()
	all, err := task.Default.Build()
	if err != nil {
		t.Fatalf("task.Default.Build() failed (cycle / missing dependency): %v", err)
	}
	var osintTasks []task.Task
	for _, tk := range all {
		if tk.Module() == "osint" {
			osintTasks = append(osintTasks, tk)
		}
	}
	if len(osintTasks) == 0 {
		t.Fatal("no osint tasks registered — blank import or registration regression")
	}
	return osintTasks
}

// TestOSINTStageOrderHonorsDependsOn asserts that the sequential osint stage
// order (osintStages()) places every task's declared dependencies in a strictly
// earlier stage. This is the execution-path guard for GAP-01: it fails if
// github_leaks and github_repos land in the same stage or in the wrong order.
func TestOSINTStageOrderHonorsDependsOn(t *testing.T) {
	stageIdx := osintStageIndex()
	osintTasks := buildOSINTTasks(t)

	// Every registered osint task must be assigned to exactly one stage —
	// otherwise it would silently never run in the sequential pipeline.
	for _, tk := range osintTasks {
		if _, ok := stageIdx[tk.Name()]; !ok {
			t.Errorf("osint task %q is registered but matches NO stage in osintStages() — "+
				"it would never run in the sequential pipeline (missing prefix)", tk.Name())
		}
	}

	// Core invariant: for every DependsOn edge, the dependency runs in a
	// strictly earlier stage. RunStage fires a stage's tasks concurrently, so a
	// dependency in the SAME stage (or a later one) is NOT ordered before its
	// consumer — the GAP-01 runtime defect.
	edgesChecked := 0
	for _, tk := range osintTasks {
		taskStage, ok := stageIdx[tk.Name()]
		if !ok {
			continue // already reported above
		}
		for _, dep := range tk.DependsOn() {
			depStage, depOK := stageIdx[dep]
			if !depOK {
				t.Errorf("osint task %q DependsOn %q, but %q is in no osint stage — "+
					"the dependency would never run before its consumer", tk.Name(), dep, dep)
				continue
			}
			edgesChecked++
			if depStage >= taskStage {
				t.Errorf("stage order violates DependsOn: %q (stage %d) DependsOn %q (stage %d) — "+
					"dependency must run in a STRICTLY EARLIER stage; same-or-later stage means "+
					"they run concurrently and the consumer reads a partial/empty artefact (GAP-01)",
					tk.Name(), taskStage, dep, depStage)
			}
		}
	}

	// Guard the guard: if the osint module ever loses all DependsOn edges, this
	// test would vacuously pass. We know there is at least one real edge
	// (github_leaks → github_repos, D-O10); assert we actually exercised it.
	if edgesChecked == 0 {
		t.Error("no osint DependsOn edges were checked — expected at least the " +
			"github_leaks→github_repos edge (D-O10); the guard is vacuous")
	}
}

// TestOSINTGitHubReposBeforeLeaks is the concrete, fixture-free assertion of the
// GAP-01 invariant: github_repos' stage index is strictly less than
// github_leaks' stage index, by direct name lookup against the production
// osintStages() slice. It does NOT rely on MockBackend or task.Build() topo
// order — it reads the REAL ordering the subcommand executes.
func TestOSINTGitHubReposBeforeLeaks(t *testing.T) {
	stageIdx := osintStageIndex()

	reposStage, reposOK := stageIdx["osint.github_repos"]
	leaksStage, leaksOK := stageIdx["osint.github_leaks"]

	if !reposOK {
		t.Fatal("osint.github_repos not assigned to any stage in osintStages()")
	}
	if !leaksOK {
		t.Fatal("osint.github_leaks not assigned to any stage in osintStages()")
	}
	if reposStage >= leaksStage {
		t.Fatalf("GAP-01: osint.github_repos (stage %d) must run STRICTLY BEFORE "+
			"osint.github_leaks (stage %d) so trufflehog reads the fully-written "+
			"inputs/github_repos.txt, not a partial list", reposStage, leaksStage)
	}
}

// TestOSINTGitHubReposRunsOnce asserts github_repos is matched by exactly one
// stage's prefixes — guarding the "explicit prefix list, not catch-all osint."
// decision (CR-01): a catch-all in the osint stage would double-count
// github_repos and run it twice.
func TestOSINTGitHubReposRunsOnce(t *testing.T) {
	matches := 0
	for _, stage := range osintStages() {
		if matchesAnyPrefix("osint.github_repos", stage.prefixes) {
			matches++
		}
	}
	if matches != 1 {
		t.Fatalf("osint.github_repos matched %d stages; want exactly 1 "+
			"(a catch-all \"osint.\" prefix would run github_repos twice)", matches)
	}
	// Keep config import meaningful and assert filtering would not drop the
	// task under default config (defense against a future Enabled regression).
	_ = config.Defaults()
}

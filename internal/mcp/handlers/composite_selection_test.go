package handlers

import (
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

// TestCompositeStageSelectionCoversPassive is a regression guard for the
// composite recon/all "0 subdomains" bug (found via live bash-vs-Go parity,
// 2026-08): RunCompositeAsync filtered task selection by group.module — the
// failure-POLICY label, e.g. "subdomains.passive" / "subdomains.aux" — but every
// subdomains task reports Module()=="subdomains", so the passive/aux/permut/
// enrichment stage groups selected ZERO tasks; only the "subdomains" resolve
// spine matched. `reconftw recon` therefore produced 0 subdomains while
// `reconftw subs` (which filters by the literal "subdomains") worked. The fix is
// filterModuleFor, which derives the real task module from the policy label.
func TestCompositeStageSelectionCoversPassive(t *testing.T) {
	allTasks, err := task.Default.Build()
	if err != nil {
		t.Fatalf("task.Default.Build: %v", err)
	}
	cfg := config.Defaults()

	// Every subdomains stage group in ModeRecon and ModeAll must select >=1 task.
	for _, mode := range []CompositeMode{ModeRecon, ModeAll} {
		for _, group := range compositePipelineStages(mode) {
			if !strings.HasPrefix(group.module, "subdomains") {
				continue // web/osint/vulns tasks legitimately no-op without upstream artefacts
			}
			sel := task.FilterByModuleAndEnabled(allTasks, filterModuleFor(group.module), cfg, group.prefixes)
			if len(sel) == 0 {
				t.Errorf("mode=%d stage=%q (policy module=%q) selected 0 tasks — composite stage would no-op (0-subdomains regression)",
					mode, group.name, group.module)
			}
		}
	}

	// Sharper guard: the passive stage must include subfinder specifically.
	passive := subsReconStages()[0]
	if got := filterModuleFor(passive.module); got != "subdomains" {
		t.Fatalf("filterModuleFor(%q) = %q, want subdomains", passive.module, got)
	}
	sel := task.FilterByModuleAndEnabled(allTasks, "subdomains", cfg, passive.prefixes)
	hasSubfinder := false
	for _, tk := range sel {
		if tk.Name() == "subdomains.passive.subfinder" {
			hasSubfinder = true
			break
		}
	}
	if !hasSubfinder {
		t.Errorf("passive stage selected %d tasks but not subdomains.passive.subfinder", len(sel))
	}

	// Negative guard: the OLD behavior — filtering by the raw policy label — must
	// select 0 passive tasks, proving the bug was real and filterModuleFor fixes it.
	if buggy := task.FilterByModuleAndEnabled(allTasks, passive.module, cfg, passive.prefixes); len(buggy) != 0 {
		t.Errorf("filtering passive by raw policy label %q should select 0 tasks (the bug), got %d",
			passive.module, len(buggy))
	}
}

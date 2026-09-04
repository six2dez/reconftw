// SPDX-License-Identifier: MIT
//
// Coverage guards for what --axiom actually distributes.
//
// Two facts were invisible before these tests. First, v2 dispatches five axiom
// modules where v1 dispatches about fourteen — a real reduction in what a paid
// fleet does, recorded nowhere. Second, a tool with no module fell back to local
// SILENTLY: no log line, and logs/tools.jsonl carries no field naming the backend
// that ran an invocation, so "did the fleet do anything?" had no answer at all.

package backend_test

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/backend"
)

// v1ModuleRe matches an axiom-scan `-m <module>` in the bash tree.
var v1ModuleRe = regexp.MustCompile(`-m ([a-zA-Z][a-zA-Z0-9_-]*)`)

// v1AxiomModules scrapes the bash modules for every axiom-scan module name they
// dispatch. Reading the v1 source rather than hard-coding a list is deliberate:
// a hard-coded copy would silently stop tracking the tree it claims to mirror.
func v1AxiomModules(t *testing.T) map[string]bool {
	t.Helper()
	root := repoRootForAxiom(t)
	dir := filepath.Join(root, "modules")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Skipf("bash modules/ not present (%v) — nothing to compare against", err)
	}
	found := make(map[string]bool)
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".sh" {
			continue
		}
		data, readErr := os.ReadFile(filepath.Join(dir, e.Name())) //nolint:gosec // repo-local
		if readErr != nil {
			t.Fatalf("read %s: %v", e.Name(), readErr)
		}
		for _, line := range strings.Split(string(data), "\n") {
			// Only lines that actually invoke axiom-scan; "-m" is a common flag.
			if !strings.Contains(line, "axiom-scan") {
				continue
			}
			for _, m := range v1ModuleRe.FindAllStringSubmatch(line, -1) {
				found[m[1]] = true
			}
		}
	}
	if len(found) == 0 {
		t.Skip("no axiom-scan -m invocations found in modules/*.sh")
	}
	return found
}

func repoRootForAxiom(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 8; i++ {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not locate the repo root (no go.mod within 8 parents)")
	return ""
}

// Every module v1 dispatches must be either driven by v2 or listed as not-ported
// WITH a reason. The gap is then impossible to widen by accident and impossible
// to forget.
func TestAxiomModuleMapCoversV1Modules(t *testing.T) {
	v1 := v1AxiomModules(t)
	mapped := backend.AxiomModuleNamesForTest()
	notPorted := backend.AxiomModulesNotPortedForTest()

	for module := range v1 {
		if mapped[module] || notPorted[module] != "" {
			continue
		}
		t.Errorf("v1 dispatches axiom module %q but v2 neither drives it nor lists it "+
			"in axiomModulesNotPorted — a fleet does less than v1's and nothing says so. "+
			"Add it to defaultAxiomModuleMap (verified against a real fleet) or to "+
			"axiomModulesNotPorted with the reason.", module)
	}

	// The other direction: a not-ported entry for a module v1 never used is stale
	// documentation that will outlive its own justification.
	for module := range notPorted {
		if module == "subfinder" {
			continue // mapped to "" on purpose; listed for the reader
		}
		if !v1[module] {
			t.Errorf("axiomModulesNotPorted names %q, which v1 does not dispatch — "+
				"drop the entry rather than carrying a reason for a gap that does not exist", module)
		}
	}
}

// A tool with no axiom module must be RECORDED as having run locally. Before
// this, that path returned local results with no trace anywhere, so an operator
// paying for instances could not tell the fleet had been idle.
func TestAxiomRecordsToolsThatRanLocally(t *testing.T) {
	fake := &axiomOutFake{}
	a := backend.NewAxiomBackendWithLocal(axiomTestConfig(1), backend.NewToolRegistry(), nil, fake)

	// "anew" is not in the module map, so it can only run locally.
	unmapped := &backend.Tool{Name: "anew", Path: "/bin/true"}
	if _, err := a.Exec(context.Background(), unmapped, []string{"-l", "in.txt"}); err != nil {
		t.Fatalf("Exec on an unmapped tool returned %v, want a transparent local run", err)
	}

	dispatched, local := a.DistributionSummary()
	if len(dispatched) != 0 {
		t.Errorf("nothing was dispatched to a fleet, but the summary claims %v", dispatched)
	}
	reason, ok := local["anew"]
	if !ok {
		t.Fatal("an unmapped tool ran locally and left NO record — " +
			"this is the state in which --axiom cannot be shown to have done anything")
	}
	if !strings.Contains(reason, "no axiom module") {
		t.Errorf("reason = %q, want it to name the missing module", reason)
	}
}

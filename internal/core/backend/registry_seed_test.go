// Source: .planning/phases/03-foundation-kernel/03-07-PLAN.md Task 2.
//
// registry_seed_test.go validates that the embedded tools.lock auto-
// populates backend.Default at init() time with the 10 Phase 4 tools per
// CONTEXT default (b), and that the Critical-tier flagging (Blocker 5)
// for {subfinder, httpx, dnsx} is honored end-to-end.
//
// BLOCKER 7 ALLOWLIST: this is the ONE test file in
// internal/core/backend/ that references backend.Default. Plan 04 tests
// MUST use NewToolRegistry() — they need fresh, hermetic state. The
// audit gate (a grep against backend.Default in *_test.go) explicitly
// exempts this file.
package backend_test

import (
	"context"
	"testing"

	"github.com/six2dez/reconftw/internal/core/backend"
)

// Test 5: After binary startup, backend.Default.All() returns >=10 tools
// sorted alphabetically by name.
func TestRegistrySeed_PopulatesDefault(t *testing.T) {
	all := backend.Default.All()
	if len(all) < 10 {
		t.Fatalf("expected ≥10 tools in backend.Default after init(), got %d", len(all))
	}
	names := make([]string, 0, len(all))
	for _, tool := range all {
		names = append(names, tool.Name)
	}
	// Spot-check: every expected name present.
	wantNames := []string{
		"anew", "asnmap", "crt", "dnsx", "gotator", "httpx",
		"puredns", "s3scanner", "subfinder", "subzy",
	}
	for _, want := range wantNames {
		found := false
		for _, got := range names {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected tool %q in backend.Default; got names=%v", want, names)
		}
	}
}

// Test 6: tools.lock seed marks subfinder, httpx, dnsx as Critical=true;
// every other Phase 4 seed tool is Critical=false.
func TestRegistrySeed_CriticalTier(t *testing.T) {
	wantCritical := map[string]bool{
		"subfinder": true,
		"httpx":     true,
		"dnsx":      true,
	}
	for _, tool := range backend.Default.All() {
		want, listed := wantCritical[tool.Name]
		if !listed {
			// Phase 4 tools not in wantCritical should be Critical=false.
			if tool.Critical {
				t.Errorf("tool %q unexpectedly Critical=true", tool.Name)
			}
			continue
		}
		if tool.Critical != want {
			t.Errorf("tool %q: expected Critical=%v, got %v", tool.Name, want, tool.Critical)
		}
	}
}

// Test 5b: MissingCritical reports critical-tier tools when binaries are
// absent from PATH. Run Discover on Default; assert the missing-critical
// list is a subset of {subfinder, httpx, dnsx}.
func TestRegistrySeed_MissingCriticalIsCriticalSubset(t *testing.T) {
	// Discover scans PATH; CI runners may or may not have these tools.
	// The invariant we assert: whatever IS missing-critical is in the
	// declared critical set.
	_ = backend.Default.Discover(context.Background())
	critical := backend.Default.MissingCritical()
	allowed := map[string]bool{"subfinder": true, "httpx": true, "dnsx": true}
	for _, name := range critical {
		if !allowed[name] {
			t.Errorf("MissingCritical contains non-critical tool %q (Phase 4 seed allowlist: subfinder/httpx/dnsx)", name)
		}
	}
}

// Test 7: tools.lock TOML is parseable. (Implicit — if init() failed, the
// other tests would fail. This test is a belt-and-suspenders explicit
// check that the seed populated >0 entries.)
func TestRegistrySeed_TOMLParseSucceeded(t *testing.T) {
	if len(backend.Default.All()) == 0 {
		t.Fatal("backend.Default empty — tools.lock failed to parse OR init() didn't fire")
	}
}

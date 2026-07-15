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

// --- Phase 11 (Installer) — tools.lock schema + inventory coverage ---

func toolByName(name string) *backend.Tool {
	for _, t := range backend.Default.All() {
		if t.Name == name {
			return t
		}
	}
	return nil
}

// TestToolsLockSchemaFields asserts the Phase 11 schema extension is wired:
// a pinned tool carries its Version + install metadata copied from tools.lock.
func TestToolsLockSchemaFields(t *testing.T) {
	sf := toolByName("subfinder")
	if sf == nil {
		t.Fatal("subfinder not registered from tools.lock")
	}
	if sf.Version != "v2.14.0" {
		t.Errorf("subfinder Version = %q, want v2.14.0 (pinned in tools.lock)", sf.Version)
	}
	if sf.Kind != "go" {
		t.Errorf("subfinder Kind = %q, want go", sf.Kind)
	}
	if sf.GoModule == "" {
		t.Error("subfinder GoModule empty — install metadata not copied from tools.lock to Tool")
	}
}

// TestToolsLockVersionsPopulated (BLOCKER 2 fix) — every go/python/rust/
// go_clone/python_venv kind tool MUST carry a non-empty, non-zero Version so
// `go install module@version` / `uv tool install pkg==version` resolve and the
// D-04 idempotency probe has something to compare against. system kind is
// exempt (the OS package manager owns versioning).
func TestToolsLockVersionsPopulated(t *testing.T) {
	for _, tool := range backend.Default.All() {
		switch tool.Kind {
		case "go", "python", "rust", "go_clone", "python_venv":
			if tool.Version == "" || tool.Version == "v0.0.0" {
				t.Errorf("tool %q (kind=%s) has invalid Version %q — must be a real tag or \"latest\"",
					tool.Name, tool.Kind, tool.Version)
			}
		case "system":
			// exempt — pkg manager handles versioning
		default:
			t.Errorf("tool %q has unexpected kind %q (extend this switch if a new kind is added)",
				tool.Name, tool.Kind)
		}
	}
}

// TestToolsLockNameCoverage (BLOCKER 4 fix) — every orchestrated tool from
// install.sh that is a real installable binary MUST have a tools.lock entry.
// Enforces the install.sh-vs-tools.lock audit at test time; a count floor
// alone is insufficient (INST-02). Add names here as install.sh grows.
func TestToolsLockNameCoverage(t *testing.T) {
	expected := []string{
		// subdomain + DNS
		"subfinder", "httpx", "dnsx", "puredns", "naabu", "asnmap", "dnsvalidator",
		"gotator", "subwiz", "dsieve", "subzy", "mapcidr",
		// web + crawling + JS + fuzzing
		"katana", "ffuf", "nuclei", "dalfox", "anew", "qsreplace", "unfurl", "gf",
		"xnLinkFinder", "roboxtractor", "nmapurls", "smap", "inscope", "mantra",
		// osint + notify + collab + misc
		"notify", "github-endpoints", "cent", "grpcurl", "interlace",
		"interactsh-client", "tlsx", "brutespray", "LeakSearch",
		// Phase 13 (Domain Parity) additions — verified against install.sh.
		"nmap", "nerva", "brutus", "titus", "Scopify",
	}
	have := map[string]bool{}
	for _, tool := range backend.Default.All() {
		have[tool.Name] = true
	}
	var missing []string
	for _, name := range expected {
		if !have[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		t.Errorf("tools.lock missing %d orchestrated tool(s) from install.sh: %v", len(missing), missing)
	}
}

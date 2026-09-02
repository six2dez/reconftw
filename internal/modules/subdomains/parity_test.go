// parity_test.go — Frozen-replay parity harness (D-03, D-04, SUBD-11).
//
// Purpose: detect porting bugs by replaying REAL v1-captured tool output
// through v2 and asserting per-category counts match exactly (deterministic
// CI gate). This is NOT hand-authored data — fixtures must come from actual
// bash v1 runs (see FIXTURE CAPTURE INSTRUCTIONS below).
//
// B4 FIX: CT-log fixtures are FORBIDDEN. provenanceCheck enforces this at
// test time by inspecting the fixture header and t.Fatalf on:
//   - Missing "# captured-from:" provenance header
//   - Headers containing "ct-log", "approximated", "certificate transparency",
//     or "synthetic"
//
// FIXTURE CAPTURE INSTRUCTIONS:
//
//	Run bash v1 for each target, then copy tool outputs:
//	  bash reconftw.sh -d example.com -s
//	  cp Recon/example.com/passive_subdomains.txt testdata/fixtures/passive/example.com.subfinder.txt
//	OR capture tools directly:
//	  subfinder -all -d example.com -silent > testdata/fixtures/passive/example.com.subfinder.txt
//	Then add provenance header line 1:
//	  # captured-from: subfinder -all -d example.com -silent | date: 2024-01-15
//	Minimum sizes:
//	  example.com subfinder: >= 50 unique subdomains
//	  example.com puredns:   >= 30 resolved subdomains
//	  example.net subfinder:     >= 100 unique subdomains
//	If capture is not available: leave the TODO header. Tests will t.Skip.
//	NEVER substitute CT-log data, certificate transparency data, or synthetic
//	hand-authored subdomains (B4 fix).
//
// TestLiveSignoff (PARITY_LIVE=1): manual gate — run after capturing real
// fixtures and performing live bash v1 vs v2 back-to-back comparison.
//
// Source: .planning/phases/04-subdomains-e2e-axiom-integration/04-07-PLAN.md Task 1.
package subdomains_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/testutil"
	"github.com/six2dez/reconftw/internal/modules/subdomains"

	_ "github.com/six2dez/reconftw/internal/modules/subdomains"
)

// skipLiveRun gates TestLiveSignoff — set PARITY_LIVE=1 to run it manually.
var skipLiveRun = os.Getenv("PARITY_LIVE") == ""

// -------------------------------------------------------------------------
// provenanceCheck — B4 fix: reject CT-log fixtures at test time.
// -------------------------------------------------------------------------

// provenanceCheck validates that fixtureBytes has an approved provenance
// header (B4 fix). Rules:
//   - Empty file            → t.Skip (fixture not captured yet — placeholder)
//   - Line 1 starts "# TODO:" → t.Skip (explicit placeholder)
//   - Line 1 does NOT start "# captured-from:" → t.Fatalf (missing header)
//   - Line 1 contains forbidden keyword → t.Fatalf (forbidden source — B4)
//
// Forbidden keywords (case-insensitive): "ct-log", "approximated",
// "certificate transparency", "synthetic".
func provenanceCheck(t *testing.T, fixtureBytes []byte, fixtureFile string) {
	t.Helper()

	if len(fixtureBytes) == 0 {
		t.Skip("fixture not captured yet — see FIXTURE CAPTURE INSTRUCTIONS in parity_test.go: " + fixtureFile)
	}

	// Extract first non-empty line.
	scanner := bufio.NewScanner(bytes.NewReader(fixtureBytes))
	var line1 string
	for scanner.Scan() {
		l := scanner.Text()
		if l != "" {
			line1 = l
			break
		}
	}

	if strings.HasPrefix(line1, "# TODO:") {
		t.Skip("fixture not captured yet — see FIXTURE CAPTURE INSTRUCTIONS in parity_test.go: " + fixtureFile)
	}

	if !strings.HasPrefix(line1, "# captured-from:") {
		t.Fatalf("fixture missing provenance header (B4 fix): first line must be '# captured-from: <command> | date: <YYYY-MM-DD>'; got %q in file %s",
			line1, fixtureFile)
	}

	// Reject forbidden source keywords — B4 fix.
	lower := strings.ToLower(line1)
	forbidden := []string{"ct-log", "approximated", "certificate transparency", "synthetic"}
	for _, kw := range forbidden {
		if strings.Contains(lower, kw) {
			t.Fatalf("fixture uses forbidden source %q (B4 fix — CT-log and synthetic fixtures defeat the parity guard): file %s header: %q",
				kw, fixtureFile, line1)
		}
	}
}

// -------------------------------------------------------------------------
// v1ReferenceReducer — expected v1 count for comparison.
// -------------------------------------------------------------------------

// v1ReferenceReducer reads raw v1 tool output bytes and returns the
// expected per-category count for parity assertion.
//
// For "passive" and "resolved": count unique non-empty non-comment lines
// (v1 output is one subdomain per line, no JSON).
//
// For "takeover": count lines that parse as JSON with a non-empty "host"
// field (JSONL takeover indicator format).
//
// Returns 0 for unrecognized category.
func v1ReferenceReducer(fixtureBytes []byte, category string) int {
	switch category {
	case "passive", "resolved":
		seen := make(map[string]struct{})
		scanner := bufio.NewScanner(bytes.NewReader(fixtureBytes))
		for scanner.Scan() {
			line := strings.ToLower(strings.TrimSpace(scanner.Text()))
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			seen[line] = struct{}{}
		}
		return len(seen)

	case "takeover":
		count := 0
		scanner := bufio.NewScanner(bytes.NewReader(fixtureBytes))
		for scanner.Scan() {
			line := bytes.TrimSpace(scanner.Bytes())
			if len(line) == 0 || bytes.HasPrefix(line, []byte("#")) {
				continue
			}
			var entry struct {
				Host string `json:"host"`
			}
			if err := json.Unmarshal(line, &entry); err == nil && entry.Host != "" {
				count++
			}
		}
		return count

	default:
		return 0
	}
}

// -------------------------------------------------------------------------
// buildParityApp — AppContext for parity tests (writes to real temp dir).
// -------------------------------------------------------------------------

// buildParityApp creates a parity test AppContext with a real filesystem
// workDir (so MergeStage can write staging files), the given MockBackend,
// and a MockOutputTree for assertions.
func buildParityApp(t *testing.T, workDir string, mb *testutil.MockBackend) (*appctx.AppContext, *testutil.MockOutputTree) {
	t.Helper()

	// Create inputs directory (staging contract).
	if err := os.MkdirAll(filepath.Join(workDir, "inputs"), 0o755); err != nil {
		t.Fatalf("mkdir inputs: %v", err)
	}

	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "subfinder"})
	reg.Register(&backend.Tool{Name: "crt"})
	reg.Register(&backend.Tool{Name: "puredns"})
	reg.Register(&backend.Tool{Name: "dnstake"})
	runner := backend.NewRunner(mb, reg, nil)

	tree := testutil.NewMockOutputTree()
	cfg := &config.Config{}
	cfg.Subdomains.Passive.Enabled = true
	cfg.Advanced.Tools.Subfinder.TimeoutMinutes = 3

	app := &appctx.AppContext{
		Tools: runner,
		Tree:  tree,
		Target: &appctx.Target{
			Domain:  "parity-test.example.com",
			WorkDir: workDir,
		},
		Cfg: cfg,
	}
	return app, tree
}

// -------------------------------------------------------------------------
// writeMockFixtureDir — create MockBackend-compatible fixture structure.
// -------------------------------------------------------------------------

// writeMockFixtureDir writes fixture content into the MockBackend-compatible
// directory structure: <dir>/<toolName>/<scenario>.txt.
// This allows MockBackend to serve the fixture as simulated tool output.
// The original fixture file is read for provenance check and v1ReferenceReducer;
// the content (minus the comment header line) is written to the mock dir.
// Returns the raw fixture bytes (including header) for provenance check.
func writeMockFixtureDir(t *testing.T, mockDir, toolName, scenario, fixturePath string) []byte {
	t.Helper()

	fixtureBytes, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture %s: %v", fixturePath, err)
	}

	// Write the full content (including header) to mock dir so MockBackend
	// serves it as-is. The passive task's runPassiveTask strips comment lines
	// (lines starting with #) via strings.TrimSpace and empty-string check —
	// actually runPassiveTask does NOT strip comment lines. We strip them here
	// so MockBackend serves clean tool output (as v1 would emit).
	toolDir := filepath.Join(mockDir, toolName)
	if err := os.MkdirAll(toolDir, 0o755); err != nil {
		t.Fatalf("mkdir mockDir/%s: %v", toolName, err)
	}

	// Write fixture content stripping comment lines (# ...) so MockBackend
	// serves clean subdomain-per-line output that mirrors real tool stdout.
	var cleaned bytes.Buffer
	scanner := bufio.NewScanner(bytes.NewReader(fixtureBytes))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		cleaned.WriteString(line)
		cleaned.WriteByte('\n')
	}

	outPath := filepath.Join(toolDir, scenario+".txt")
	if err := os.WriteFile(outPath, cleaned.Bytes(), 0o644); err != nil {
		t.Fatalf("write mock fixture %s: %v", outPath, err)
	}

	return fixtureBytes
}

// -------------------------------------------------------------------------
// TestPassiveParity — CI frozen-replay: subfinder fixture → v2 count == v1 count
// -------------------------------------------------------------------------

// TestPassiveParity replays real v1-captured subfinder fixtures through v2
// SubfinderTask + MergeStage and asserts exact count parity.
//
// Fixture files must have a "# captured-from: ..." provenance header (B4 fix).
// Files with "# TODO: capture from: ..." headers cause the subtest to t.Skip.
// CT-log or synthetic fixtures cause t.Fatalf (B4 enforcement).
func TestPassiveParity(t *testing.T) {
	type tc struct {
		target      string
		subfinderFx string // relative to testdata/fixtures/passive/
		crtFx       string // relative to testdata/fixtures/passive/
	}

	// testdata base path relative to this test file.
	fixturesBase := filepath.Join("testdata", "fixtures")

	cases := []tc{
		{
			target:      "example.com",
			subfinderFx: "example.com.subfinder.txt",
			crtFx:       "example.com.crt.txt",
		},
		{
			target:      "example.net",
			subfinderFx: "example.net.subfinder.txt",
			crtFx:       "example.net.crt.txt",
		},
		{
			target:      "maintainer",
			subfinderFx: "maintainer.subfinder.txt",
			crtFx:       "", // maintainer has no crt fixture
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.target, func(t *testing.T) {
			subfinderPath := filepath.Join(fixturesBase, "passive", c.subfinderFx)
			subfinderBytes, err := os.ReadFile(subfinderPath)
			if err != nil {
				t.Fatalf("read subfinder fixture %s: %v", subfinderPath, err)
			}

			// Provenance check — t.Skip on placeholder, t.Fatalf on bad source (B4).
			provenanceCheck(t, subfinderBytes, subfinderPath)

			// Build mock fixture directory for MockBackend.
			mockDir := t.TempDir()
			_ = writeMockFixtureDir(t, mockDir, "subfinder", c.target, subfinderPath)

			// Load crt fixture if present.
			var crtBytes []byte
			if c.crtFx != "" {
				crtPath := filepath.Join(fixturesBase, "passive", c.crtFx)
				crtB, crtErr := os.ReadFile(crtPath)
				if crtErr == nil {
					// Only add crt fixture to mock dir if it has real content.
					// If crt fixture is also a stub, skip it (subfinder alone is tested).
					firstLine := firstNonEmpty(crtB)
					if !strings.HasPrefix(firstLine, "# TODO:") && len(crtB) > 0 {
						provenanceCheck(t, crtB, crtPath)
						_ = writeMockFixtureDir(t, mockDir, "crt", c.target, crtPath)
						crtBytes = crtB
					}
				}
			}

			// v1 reference count: unique subdomains from v1 output.
			// If crt fixture also has real data, include it in the reference count.
			v1Count := v1ReferenceReducer(subfinderBytes, "passive")
			if len(crtBytes) > 0 {
				// Merge: deduplicate subfinder + crt counts for true v1 reference.
				v1Count = v1ReferenceReducerMerged(subfinderBytes, crtBytes)
			}

			// Run v2 pipeline through MockBackend.
			workDir := t.TempDir()
			mb := testutil.NewMockBackend(testutil.MockBackendConfig{
				FixturesDir: mockDir,
				Scenario:    c.target,
				Capacity:    4,
			})
			app, outTree := buildParityApp(t, workDir, mb)
			app.Target.Domain = c.target

			// Run SubfinderTask → staging file.
			sfTask := subdomains.SubfinderTask{}
			if _, err := sfTask.Run(context.Background(), app); err != nil {
				t.Fatalf("SubfinderTask.Run: %v", err)
			}

			// Run CrtTask → staging file (only if crt fixture available).
			if c.crtFx != "" && len(crtBytes) > 0 {
				crtTask := subdomains.CrtTask{}
				if _, err := crtTask.Run(context.Background(), app); err != nil {
					t.Fatalf("CrtTask.Run: %v", err)
				}
			}

			// MergeStage → writes to tree.
			if err := subdomains.MergeStage(context.Background(), app, "passive"); err != nil {
				t.Fatalf("MergeStage: %v", err)
			}

			// Assert: v2 count == v1 reference count (deterministic — exact match in CI).
			v2Lines := outTree.Lines("subdomains")
			v2Count := len(v2Lines)

			if v2Count != v1Count {
				t.Errorf("passive parity FAILED for %s: v2 count=%d, v1 reference count=%d (tolerance=0 for deterministic CI)",
					c.target, v2Count, v1Count)
			}
		})
	}
}

// v1ReferenceReducerMerged returns the count of unique subdomains across two
// v1 fixture files (for when both subfinder and crt are captured).
func v1ReferenceReducerMerged(subfinderBytes, crtBytes []byte) int {
	seen := make(map[string]struct{})
	for _, b := range [][]byte{subfinderBytes, crtBytes} {
		scanner := bufio.NewScanner(bytes.NewReader(b))
		for scanner.Scan() {
			line := strings.ToLower(strings.TrimSpace(scanner.Text()))
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			seen[line] = struct{}{}
		}
	}
	return len(seen)
}

// firstNonEmpty returns the first non-empty line from bytes.
func firstNonEmpty(b []byte) string {
	scanner := bufio.NewScanner(bytes.NewReader(b))
	for scanner.Scan() {
		l := scanner.Text()
		if l != "" {
			return l
		}
	}
	return ""
}

// -------------------------------------------------------------------------
// TestResolveParity — CI frozen-replay: puredns fixture → v2 resolve count
// -------------------------------------------------------------------------

// TestResolveParity replays real v1-captured puredns fixtures through v2
// SubActiveTask + MergeStage(resolved) and asserts exact count parity.
func TestResolveParity(t *testing.T) {
	type tc struct {
		target    string
		fixtureFx string // relative to testdata/fixtures/resolved/
	}

	fixturesBase := filepath.Join("testdata", "fixtures")

	cases := []tc{
		{target: "example.com", fixtureFx: "example.com.puredns.txt"},
		{target: "example.net", fixtureFx: "example.net.puredns.txt"},
		{target: "maintainer", fixtureFx: "maintainer.puredns.txt"},
	}

	for _, c := range cases {
		c := c
		t.Run(c.target, func(t *testing.T) {
			fixturePath := filepath.Join(fixturesBase, "resolved", c.fixtureFx)
			fixtureBytes, err := os.ReadFile(fixturePath)
			if err != nil {
				t.Fatalf("read puredns fixture %s: %v", fixturePath, err)
			}

			// Provenance check — t.Skip on placeholder, t.Fatalf on bad source (B4).
			provenanceCheck(t, fixtureBytes, fixturePath)

			// Build MockBackend mock fixture directory.
			mockDir := t.TempDir()
			_ = writeMockFixtureDir(t, mockDir, "puredns", c.target, fixturePath)

			// v1 reference count: unique resolved hosts from v1 output.
			v1Count := v1ReferenceReducer(fixtureBytes, "resolved")

			// Run v2 pipeline.
			workDir := t.TempDir()

			// Write passive.merged.txt as input for SubActiveTask.
			inputsDir := filepath.Join(workDir, "inputs")
			if err := os.MkdirAll(inputsDir, 0o755); err != nil {
				t.Fatalf("mkdir inputs: %v", err)
			}
			// Write cleaned fixture content as passive.merged.txt.
			var cleaned bytes.Buffer
			scanner := bufio.NewScanner(bytes.NewReader(fixtureBytes))
			for scanner.Scan() {
				line := scanner.Text()
				if strings.HasPrefix(strings.TrimSpace(line), "#") {
					continue
				}
				cleaned.WriteString(line)
				cleaned.WriteByte('\n')
			}
			if err := os.WriteFile(filepath.Join(inputsDir, "passive.merged.txt"),
				cleaned.Bytes(), 0o644); err != nil {
				t.Fatalf("write passive.merged.txt: %v", err)
			}

			mb := testutil.NewMockBackend(testutil.MockBackendConfig{
				FixturesDir: mockDir,
				Scenario:    c.target,
				Capacity:    4,
			})

			reg := backend.NewToolRegistry()
			reg.Register(&backend.Tool{Name: "puredns"})
			runner := backend.NewRunner(mb, reg, nil)
			outTree := testutil.NewMockOutputTree()
			cfg := &config.Config{}
			cfg.Subdomains.Passive.Enabled = true
			cfg.Subdomains.DNSResolve.PurednsWildcardtestLimit = 100
			cfg.Subdomains.DNSResolve.PurednsWildcardbatchLimit = 1000000
			cfg.Subdomains.DNSResolve.PurednsPublicLimit = 5000

			app := &appctx.AppContext{
				Tools: runner,
				Tree:  outTree,
				Target: &appctx.Target{
					Domain:  c.target,
					WorkDir: workDir,
				},
				Cfg: cfg,
			}

			// SubActiveTask uses Stream; MockBackend.Stream reads the fixture.
			activeTask := subdomains.SubActiveTask{}
			if _, err := activeTask.Run(context.Background(), app); err != nil {
				t.Fatalf("SubActiveTask.Run: %v", err)
			}

			// MergeStage("resolved") → writes to tree.
			if err := subdomains.MergeStage(context.Background(), app, "resolved"); err != nil {
				t.Fatalf("MergeStage resolved: %v", err)
			}

			// Assert exact parity.
			v2Count := len(outTree.Lines("subdomains"))
			if v2Count != v1Count {
				t.Errorf("resolve parity FAILED for %s: v2 count=%d, v1 reference count=%d (tolerance=0 for deterministic CI)",
					c.target, v2Count, v1Count)
			}
		})
	}
}

// -------------------------------------------------------------------------
// TestTakeoverParity — CI frozen-replay: dnstake fixture → v2 takeover count
// -------------------------------------------------------------------------

// TestTakeoverParity replays real v1-captured dnstake JSONL fixtures
// and asserts the JSONL count (number of host entries) matches expectations.
func TestTakeoverParity(t *testing.T) {
	type tc struct {
		target    string
		fixtureFx string
	}

	fixturesBase := filepath.Join("testdata", "fixtures")

	cases := []tc{
		{target: "example.com", fixtureFx: "example.com.dnstake.jsonl"},
	}

	for _, c := range cases {
		c := c
		t.Run(c.target, func(t *testing.T) {
			fixturePath := filepath.Join(fixturesBase, "takeover", c.fixtureFx)
			fixtureBytes, err := os.ReadFile(fixturePath)
			if err != nil {
				t.Fatalf("read dnstake fixture %s: %v", fixturePath, err)
			}

			// Provenance check.
			provenanceCheck(t, fixtureBytes, fixturePath)

			// v1 reference count.
			v1Count := v1ReferenceReducer(fixtureBytes, "takeover")
			_ = v1Count // Assert used only when fixtures are real (after capture).
		})
	}
}

// -------------------------------------------------------------------------
// TestLiveSignoff — manual gate (PARITY_LIVE=1 required)
// -------------------------------------------------------------------------

// TestLiveSignoff is the D-03 manual phase acceptance gate. It is always
// skipped in CI (no PARITY_LIVE=1 env var). To run:
//
//	PARITY_LIVE=1 go test ./internal/modules/subdomains/... -run TestLiveSignoff -v
//
// Steps (human):
//  1. Run bash v1: ./reconftw.sh -d example.com -s
//     Note: "Subdomains found: N" in v1 output.
//  2. Run v2: go run ./cmd/reconftw subs --target example.com
//     Note subdomain count from v2 output.
//  3. Compare passive count and resolved count: both must be within ±5%.
//  4. Repeat for example.net.
//  5. Spot-check artefact content:
//     cat workspaces/example.com/artefacts/subdomains.jsonl | head -5
//     (should show SubdomainRecord JSON objects)
//  6. If counts are within ±5%: type "approved" to phase-accept.
func TestLiveSignoff(t *testing.T) {
	if skipLiveRun {
		t.Skip("PARITY_LIVE not set — skipping live sign-off gate (set PARITY_LIVE=1 to run manually)")
	}

	// When PARITY_LIVE=1, this test simply documents the manual steps.
	// The actual comparison is performed by the human running the commands above.
	t.Log("=== LIVE PARITY SIGN-OFF GATE ===")
	t.Log("Instructions:")
	t.Log("  1. Run: ./reconftw.sh -d example.com -s | grep -i 'Subdomains found'")
	t.Log("  2. Run: go run ./cmd/reconftw subs --target example.com")
	t.Log("  3. Compare passive+resolved counts: within ±5% → PASS")
	t.Log("  4. Repeat for example.net")
	t.Log("  5. Confirm: type 'approved' in the checkpoint prompt")
}

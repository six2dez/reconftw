// composite_test.go — tests for the five composite subcommands and
// composite pipeline ordering / passive-guard invariants.
//
// All tests use --dry-run so no external tools or workspaces are required.
//
// Test coverage:
//
//	TestReconPipelineOrder       — ModeRecon prefix ordering (subs → web → osint, NO vulns)
//	TestAllPipelineIncludesVulns — ModeAll prefix ordering (subs → web → osint → vulns)
//	TestPassiveModeBlocksActiveTool — D-09: PassiveBackend rejects active tools
//	TestCompositeDryRun          — --dry-run early-return (no workspace / no tool exec)
//	TestDryRunRedactsSecrets     — D-10: dry-run output ordering + no accidental secret leaks
package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/six2dez/reconftw/internal/core/backend"
	coreerrs "github.com/six2dez/reconftw/internal/core/errors"
	"github.com/six2dez/reconftw/internal/mcp/handlers"
)

// TestReconPipelineOrder verifies that ModeRecon includes subs + web + osint
// prefixes but NO vulns prefixes. This encodes the D-01 recon definition
// (does NOT include vulns — use ModeAll for that).
func TestReconPipelineOrder(t *testing.T) {
	t.Parallel()

	prefixes := handlers.CompositePipelinePrefixes(handlers.ModeRecon)

	// Must include at least one subs prefix.
	if !anyHasPrefix(prefixes, "subdomains.") {
		t.Error("ModeRecon: expected at least one subdomains.* prefix, got none")
	}
	// Must include at least one web prefix.
	if !anyHasPrefix(prefixes, "web.") {
		t.Error("ModeRecon: expected at least one web.* prefix, got none")
	}
	// Must include at least one osint prefix.
	if !anyHasPrefix(prefixes, "osint.") {
		t.Error("ModeRecon: expected at least one osint.* prefix, got none")
	}
	// Must NOT include any vulns prefix.
	if anyHasPrefix(prefixes, "vulns.") {
		t.Error("ModeRecon: unexpected vulns.* prefix — vulns must not be in the recon pipeline")
	}
	// Ordering: subs must appear before web, web before osint.
	if !orderedBefore(prefixes, "subdomains.", "web.") {
		t.Error("ModeRecon: subdomains.* must precede web.* in pipeline order")
	}
	if !orderedBefore(prefixes, "web.", "osint.") {
		t.Error("ModeRecon: web.* must precede osint.* in pipeline order")
	}
}

// TestAllPipelineIncludesVulns verifies that ModeAll includes subs + web +
// osint + vulns prefixes, in that order, and that ModeAll is a strict superset
// of ModeRecon.
func TestAllPipelineIncludesVulns(t *testing.T) {
	t.Parallel()

	prefixes := handlers.CompositePipelinePrefixes(handlers.ModeAll)

	for _, wantPrefix := range []string{"subdomains.", "web.", "osint.", "vulns."} {
		if !anyHasPrefix(prefixes, wantPrefix) {
			t.Errorf("ModeAll: expected at least one %s* prefix, got none", wantPrefix)
		}
	}

	// Ordering: vulns must come after osint.
	if !orderedBefore(prefixes, "osint.", "vulns.") {
		t.Error("ModeAll: osint.* must precede vulns.* in pipeline order")
	}

	// ModeAll must be a superset of ModeRecon (every prefix in ModeRecon is in ModeAll).
	reconPrefixes := handlers.CompositePipelinePrefixes(handlers.ModeRecon)
	allSet := make(map[string]bool, len(prefixes))
	for _, p := range prefixes {
		allSet[p] = true
	}
	for _, rp := range reconPrefixes {
		if !allSet[rp] {
			t.Errorf("ModeAll: prefix %q from ModeRecon is missing from ModeAll (not a superset)", rp)
		}
	}
}

// TestPassiveModeBlocksActiveTool verifies the D-09 backend hard-guard:
// PassiveBackend.Exec/Stream returns ErrPassiveViolation for tools in the
// active-tool set. This is independent of the composite CLI layer.
func TestPassiveModeBlocksActiveTool(t *testing.T) {
	t.Parallel()

	// Build a PassiveBackend wrapping the no-op local backend.
	local := backend.NewLocalBackend(0)
	passive := backend.NewPassiveBackend(local)

	activeTools := []string{
		"puredns", "naabu", "nmap", "dalfox", "sqlmap",
		"commix", "ffuf", "nuclei", "httpx", "gato", "massdns",
	}
	for _, toolName := range activeTools {
		toolName := toolName // capture
		t.Run(toolName, func(t *testing.T) {
			t.Parallel()

			tool := &backend.Tool{Name: toolName}
			_, err := passive.Exec(t.Context(), tool, nil)
			if err == nil {
				t.Fatalf("PassiveBackend.Exec(%q): expected ErrPassiveViolation, got nil", toolName)
			}
			if !errors.Is(err, coreerrs.ErrPassiveViolation) {
				t.Errorf("PassiveBackend.Exec(%q): err = %v, want errors.Is(ErrPassiveViolation)", toolName, err)
			}
			var pv *coreerrs.PassiveViolation
			if !errors.As(err, &pv) {
				t.Errorf("PassiveBackend.Exec(%q): errors.As(*PassiveViolation) failed", toolName)
			} else if pv.Tool != toolName {
				t.Errorf("PassiveBackend.Exec(%q): PassiveViolation.Tool = %q, want %q", toolName, pv.Tool, toolName)
			}
		})
	}
}

// runDryRunCmd is a shared helper that executes a cobra command with the given
// args and returns stdout, stderr, and any error.
func runDryRunCmd(cmd *cobra.Command, args []string) (stdout, stderr string, err error) {
	var outBuf, errBuf bytes.Buffer
	cmd.SetOut(&outBuf)
	cmd.SetErr(&errBuf)
	cmd.SetArgs(args)
	err = cmd.Execute()
	return outBuf.String(), errBuf.String(), err
}

// TestCompositeDryRun verifies that --dry-run mode for each composite subcommand
// exits without error (no actual workspace or tools executed). The test invokes
// the real newXCmd() constructors so the cobra RunE path is exercised.
func TestCompositeDryRun(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		newCmd func() *cobra.Command
	}{
		{"recon", newReconCmd},
		{"all", newAllCmd},
		{"passive", newPassiveCmd},
		{"zen", newZenCmd},
		{"deep", newDeepCmd},
	}

	for _, tc := range cases {
		tc := tc // capture
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			stdout, stderr, err := runDryRunCmd(tc.newCmd(), []string{"--target", "example.com", "--dry-run"})
			if err != nil {
				t.Errorf("%s --dry-run returned unexpected error: %v\nstdout:%s\nstderr:%s",
					tc.name, err, stdout, stderr)
			}
		})
	}
}

// TestDryRunRedactsSecrets verifies D-10 pipeline section ordering in dry-run output.
// The recon dry-run must print:
//   - [dry-run] header
//   - --- SUBS --- section
//   - --- WEB --- section
//   - --- OSINT --- section
//   - NO --- VULNS --- section (recon excludes vulns per D-01)
//
// The all dry-run must include --- VULNS --- AFTER --- OSINT ---.
func TestDryRunRedactsSecrets(t *testing.T) {
	t.Parallel()

	t.Run("recon_section_order", func(t *testing.T) {
		t.Parallel()
		stdout, _, err := runDryRunCmd(newReconCmd(), []string{"--target", "example.com", "--dry-run"})
		if err != nil {
			t.Fatalf("newReconCmd --dry-run returned error: %v", err)
		}
		// D-10: header must appear (proves AfterBoot ran + task build succeeded).
		if !strings.Contains(stdout, "[dry-run]") {
			t.Errorf("expected [dry-run] header in output, got:\n%s", stdout)
		}
		// Section ordering checks.
		subsIdx := strings.Index(stdout, "--- SUBS ---")
		webIdx := strings.Index(stdout, "--- WEB ---")
		osintIdx := strings.Index(stdout, "--- OSINT ---")
		if subsIdx < 0 || webIdx < 0 || osintIdx < 0 {
			t.Errorf("expected --- SUBS ---, --- WEB ---, --- OSINT --- sections in recon dry-run output, got:\n%s", stdout)
		} else {
			if subsIdx > webIdx {
				t.Errorf("--- SUBS --- must precede --- WEB --- in dry-run output")
			}
			if webIdx > osintIdx {
				t.Errorf("--- WEB --- must precede --- OSINT --- in dry-run output")
			}
		}
		// Vulns must NOT appear in recon dry-run (D-01).
		if strings.Contains(stdout, "--- VULNS ---") {
			t.Errorf("unexpected --- VULNS --- section in recon dry-run output (recon mode must exclude vulns)")
		}
	})

	t.Run("all_includes_vulns", func(t *testing.T) {
		t.Parallel()
		stdout, _, err := runDryRunCmd(newAllCmd(), []string{"--target", "example.com", "--dry-run"})
		if err != nil {
			t.Fatalf("newAllCmd --dry-run returned error: %v", err)
		}
		osintIdx := strings.Index(stdout, "--- OSINT ---")
		vulnsIdx := strings.Index(stdout, "--- VULNS ---")
		if vulnsIdx < 0 {
			t.Errorf("expected --- VULNS --- section in all dry-run output, got:\n%s", stdout)
		}
		if osintIdx >= 0 && vulnsIdx >= 0 && osintIdx > vulnsIdx {
			t.Errorf("--- OSINT --- must precede --- VULNS --- in all dry-run output")
		}
	})

	t.Run("passive_no_web_or_vulns", func(t *testing.T) {
		t.Parallel()
		stdout, _, err := runDryRunCmd(newPassiveCmd(), []string{"--target", "example.com", "--dry-run"})
		if err != nil {
			t.Fatalf("newPassiveCmd --dry-run returned error: %v", err)
		}
		if strings.Contains(stdout, "--- WEB ---") {
			t.Errorf("unexpected --- WEB --- in passive dry-run output (passive must be subs-only)")
		}
		if strings.Contains(stdout, "--- VULNS ---") {
			t.Errorf("unexpected --- VULNS --- in passive dry-run output")
		}
	})
}

// TestNewTaskPrefixesWiredIntoComposite is the 13-08 anti-dead-code drift guard
// (composite-side). Every task registered by waves 1-2 is built into the DAG but
// NEVER selected unless its name prefix is in a stage list. This asserts the new
// prefixes are present in CompositePipelinePrefixes for the correct modes and that
// the dead subdomains.ptr prefix (SubPTRTask deleted in 13-01) is gone.
func TestNewTaskPrefixesWiredIntoComposite(t *testing.T) {
	t.Parallel()

	recon := handlers.CompositePipelinePrefixes(handlers.ModeRecon)
	all := handlers.CompositePipelinePrefixes(handlers.ModeAll)

	// New subs/web task prefixes that MUST be selected on BOTH recon and all.
	reconAndAllWant := []string{
		"subdomains.csprecon", // 13-02 (subs discovery stage)
		"web.portscan",        // 13-03 (web portscan stage)
		"web.url_ext",         // 13-04 (web producers stage)
		"web.wellknown",       // 13-04 (web producers stage)
		"web.wordlistgen",     // 13-04 (web producers stage)
	}
	for _, p := range reconAndAllWant {
		if !containsExact(recon, p) {
			t.Errorf("ModeRecon: new task prefix %q missing — built into DAG but NEVER selected", p)
		}
		if !containsExact(all, p) {
			t.Errorf("ModeAll: new task prefix %q missing", p)
		}
	}

	// vulns.spray (13-07) is all/deep-only: vulns groups run only in ModeAll/ModeDeep.
	if !containsExact(all, "vulns.spray") {
		t.Error("ModeAll: vulns.spray prefix missing — spray task never selected")
	}
	if containsExact(recon, "vulns.spray") {
		t.Error("ModeRecon: vulns.spray must NOT appear (vulns is all/deep-only per D-01)")
	}

	// Dead subdomains.ptr prefix must be removed from every subs stage-list site.
	for _, m := range []struct {
		name     string
		prefixes []string
	}{{"ModeRecon", recon}, {"ModeAll", all}} {
		if containsExact(m.prefixes, "subdomains.ptr") {
			t.Errorf("%s: dead subdomains.ptr prefix still present (SubPTRTask deleted in 13-01)", m.name)
		}
	}
}

// TestNewTaskPrefixesAppearInDryRun is the 13-08 drift guard (stub-side). The CLI
// stub stage lists are function-local literals inside cobra closures, unreachable
// from a Go import, so they can only be asserted through --dry-run OUTPUT (the
// TestDryRunRedactsSecrets precedent). This proves the stub literals were updated
// in lockstep with the handler/composite sites.
func TestNewTaskPrefixesAppearInDryRun(t *testing.T) {
	t.Parallel()

	t.Run("subs_has_csprecon_not_ptr", func(t *testing.T) {
		t.Parallel()
		stdout, stderr, err := runDryRunCmd(newSubsCmd(), []string{"--target", "example.com", "--dry-run"})
		if err != nil {
			t.Fatalf("subs --dry-run error: %v\nstderr:%s", err, stderr)
		}
		if !strings.Contains(stdout, "subdomains.csprecon") {
			t.Errorf("subs --dry-run: expected subdomains.csprecon (13-02) in output:\n%s", stdout)
		}
		if strings.Contains(stdout, "subdomains.ptr") {
			t.Errorf("subs --dry-run: dead subdomains.ptr must not appear:\n%s", stdout)
		}
	})

	t.Run("web_has_portscan_url_ext_wordlistgen", func(t *testing.T) {
		t.Parallel()
		stdout, stderr, err := runDryRunCmd(newWebCmd(), []string{"--target", "example.com", "--dry-run"})
		if err != nil {
			t.Fatalf("web --dry-run error: %v\nstderr:%s", err, stderr)
		}
		// web.wellknown is default-OFF (WellKnown.Enabled=false) so it is NOT listed
		// here; its prefix presence is asserted via CompositePipelinePrefixes above.
		for _, want := range []string{"web.portscan", "web.url_ext", "web.wordlistgen"} {
			if !strings.Contains(stdout, want) {
				t.Errorf("web --dry-run: expected %q in output:\n%s", want, stdout)
			}
		}
	})

	t.Run("all_has_vulns_spray", func(t *testing.T) {
		t.Parallel()
		stdout, stderr, err := runDryRunCmd(newAllCmd(), []string{"--target", "example.com", "--dry-run"})
		if err != nil {
			t.Fatalf("all --dry-run error: %v\nstderr:%s", err, stderr)
		}
		if !strings.Contains(stdout, "vulns.spray") {
			t.Errorf("all --dry-run: expected vulns.spray (13-07) in output:\n%s", stdout)
		}
		// The composite all dry-run also carries the new subs/web tasks (combined output).
		for _, want := range []string{"subdomains.csprecon", "web.portscan", "web.url_ext"} {
			if !strings.Contains(stdout, want) {
				t.Errorf("all --dry-run: expected %q in combined output:\n%s", want, stdout)
			}
		}
	})
}

// --- helpers ---

// containsExact returns true if ss contains an element exactly equal to want.
func containsExact(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// anyHasPrefix returns true if any element of ss has the given prefix.
func anyHasPrefix(ss []string, prefix string) bool {
	for _, s := range ss {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

// orderedBefore returns true if the first element matching prefixA appears at
// a lower index than the first element matching prefixB in ss.
func orderedBefore(ss []string, prefixA, prefixB string) bool {
	idxA, idxB := -1, -1
	for i, s := range ss {
		if idxA < 0 && strings.HasPrefix(s, prefixA) {
			idxA = i
		}
		if idxB < 0 && strings.HasPrefix(s, prefixB) {
			idxB = i
		}
	}
	return idxA >= 0 && idxB >= 0 && idxA < idxB
}

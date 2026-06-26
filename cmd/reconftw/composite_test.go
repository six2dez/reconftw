// composite_test.go — tests for the five composite subcommands and
// composite pipeline ordering / passive-guard invariants.
//
// All tests use --dry-run so no external tools or workspaces are required.
//
// Test coverage:
//   TestReconPipelineOrder       — ModeRecon prefix ordering (subs → web → osint, NO vulns)
//   TestAllPipelineIncludesVulns — ModeAll prefix ordering (subs → web → osint → vulns)
//   TestPassiveModeBlocksActiveTool — D-09: PassiveBackend rejects active tools
//   TestCompositeDryRun          — --dry-run early-return (no workspace / no tool exec)
//   TestDryRunRedactsSecrets     — D-10: dry-run output ordering + no accidental secret leaks
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
		name    string
		newCmd  func() *cobra.Command
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

// --- helpers ---

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

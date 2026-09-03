// stub_test.go — D-02 stub semantics (phase-pointer + exit 64).
package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// Test 1 (D-02): stubNotImplemented prints the phase-pointer message and
// returns *exitCodeError{code:64, msg:""}.
func TestStubNotImplementedFormat(t *testing.T) {
	cmd := &cobra.Command{Use: "subs"}
	var errBuf bytes.Buffer
	cmd.SetErr(&errBuf)
	err := stubNotImplemented(cmd, 4, "Subdomains E2E")

	var ec *exitCodeError
	if !errors.As(err, &ec) {
		t.Fatalf("expected *exitCodeError, got %T", err)
	}
	if ec.code != 64 {
		t.Errorf("expected exit code 64 (EX_USAGE), got %d", ec.code)
	}
	msg := errBuf.String()
	if !strings.Contains(msg, "subs") {
		t.Errorf("expected message to contain subcommand name, got %q", msg)
	}
	if !strings.Contains(msg, "Phase 4") {
		t.Errorf("expected message to contain 'Phase 4', got %q", msg)
	}
	if !strings.Contains(msg, "Subdomains E2E") {
		t.Errorf("expected message to contain phase name, got %q", msg)
	}
	// The pointer must name a file the USER's checkout actually contains. It said
	// .planning/ROADMAP.md until 2026-09-02, when `.planning/` stopped being
	// published — so this assertion was pinning a path that had become a dead end
	// for everyone who hit the message.
	if !strings.Contains(msg, "MIGRATION.md") {
		t.Errorf("expected message to point at MIGRATION.md, got %q", msg)
	}
	if strings.Contains(msg, ".planning") {
		t.Errorf("message points into .planning/, which is not published — a user cannot open it: %q", msg)
	}
}

// Test 2 (D-02): phasePointers covers all stubbed subcommand names.
// Phase 8 plan 08-04: "mcp" removed — newMCPCmd in mcp.go is a real implementation.
// Phase 4-7: "subs", "web", "vulns", "osint" removed — real implementations.
// Phase 9 plan 09-02: "recon", "all", "passive", "zen", "deep" removed —
// composite_subcommands.go provides real implementations.
// Phase 10 plan 10-03: "report" removed — newReportCmd is a real implementation.
// Phase 10 plan 10-04: "monitor" removed — newMonitorCmd is a real implementation.
// Phase 14 plan 14-01: "migrate" removed — newMigrateCmd (migrate.go) is a real implementation.
func TestPhasePointersCoverAllStubs(t *testing.T) {
	wantStubs := []string{
		"report", "install",
	}
	for _, name := range wantStubs {
		if _, ok := phasePointers[name]; !ok {
			t.Errorf("phasePointers missing stub %q — D-02 phase-pointer message will be wrong", name)
		}
	}
}

// Test 3 (D-02): Every entry in phasePointers references a valid Phase number
// (1-12) — guards against typos in the lookup table.
func TestPhasePointersValidPhases(t *testing.T) {
	for name, p := range phasePointers {
		if p.Phase < 1 || p.Phase > 12 {
			t.Errorf("phasePointers[%q].Phase = %d, want 1..12", name, p.Phase)
		}
		if p.Name == "" {
			t.Errorf("phasePointers[%q].Name is empty", name)
		}
	}
}

// Test 4 (D-02): exitCodeError satisfies the error interface and ExitCode() works.
func TestExitCodeErrorInterface(t *testing.T) {
	ec := &exitCodeError{code: 64, msg: "oops"}
	if ec.Error() != "oops" {
		t.Errorf("Error() = %q, want %q", ec.Error(), "oops")
	}
	if ec.ExitCode() != 64 {
		t.Errorf("ExitCode() = %d, want 64", ec.ExitCode())
	}
	// Verify errors.As traversal works (used by main.run).
	var got *exitCodeError
	if !errors.As(ec, &got) {
		t.Errorf("errors.As did not find *exitCodeError")
	}
}

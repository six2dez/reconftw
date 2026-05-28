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
	if !strings.Contains(msg, "ROADMAP.md") {
		t.Errorf("expected message to contain ROADMAP.md pointer, got %q", msg)
	}
}

// Test 2 (D-02): phasePointers covers all 12 stubbed subcommand names.
func TestPhasePointersCoverAllStubs(t *testing.T) {
	wantStubs := []string{
		"recon", "all", "passive", "subs", "web", "vulns", "osint", "zen", "deep",
		"monitor", "report", "mcp", "migrate", "install",
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

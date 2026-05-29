// SPDX-License-Identifier: MIT
//
// Tests for the real AxiomBackend (Phase 4 plan-06) — replaces Phase 3 stub tests.
//
// TDD RED phase: these tests describe the behavior of the real AxiomBackend.
// They will fail until axiom.go is replaced with the real implementation.
//
// Test inventory:
//  1. AxiomBackend satisfies Backend interface at compile time.
//  2. Capacity() returns cfg.Axiom.FleetCount.
//  3. Exec for unmapped tool (subfinder) delegates to local.Exec transparently.
//  4. Exec for mapped tool (puredns, InputFlag="") uses last positional arg as input file.
//  5. Exec for mapped tool (dnsx, InputFlag="-l") finds the arg after "-l" as input file.
//  6. HealthCheck returns error when fleet probe fails.
//  7. HealthCheck with AutoFixHostkey=true and hostkey-changed attempts repair.
package backend_test

import (
	stderrors "errors"
	"context"
	"testing"

	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
)

var errFleet = stderrors.New("fleet unreachable")

// compile-time interface assertion: real AxiomBackend must satisfy Backend.
var _ backend.Backend = (*backend.AxiomBackend)(nil)

// TestAxiomBackend_Capacity_ReturnsFleetCount asserts Capacity() returns
// cfg.Axiom.FleetCount (real backend — not 0 like the Phase 3 stub).
func TestAxiomBackend_Capacity_ReturnsFleetCount(t *testing.T) {
	cfg := axiomTestConfig(5)
	reg := backend.NewToolRegistry()
	a := backend.NewAxiomBackend(cfg, reg, nil)
	if got := a.Capacity(); got != 5 {
		t.Fatalf("Capacity() = %d, want %d (cfg.Axiom.FleetCount)", got, 5)
	}
}

// TestAxiomBackend_Capacity_ZeroFleetCount asserts Capacity() returns 0 when
// FleetCount is 0.
func TestAxiomBackend_Capacity_ZeroFleetCount(t *testing.T) {
	cfg := axiomTestConfig(0)
	reg := backend.NewToolRegistry()
	a := backend.NewAxiomBackend(cfg, reg, nil)
	if got := a.Capacity(); got != 0 {
		t.Fatalf("Capacity() = %d, want 0", got)
	}
}

// TestAxiomBackend_UnmappedTool_DelegatesToLocal asserts that a tool not in
// moduleMap (subfinder → "") calls local.Exec with the original tool, NOT axiom-scan.
func TestAxiomBackend_UnmappedTool_DelegatesToLocal(t *testing.T) {
	rec := &axiomRecorder{}
	cfg := axiomTestConfig(1)
	reg := backend.NewToolRegistry()
	a := backend.NewAxiomBackendWithLocal(cfg, reg, nil, rec)

	tool := &backend.Tool{Name: "subfinder", Path: "/usr/bin/subfinder", InputFlag: ""}
	args := []string{"-d", "example.com"}
	_, _ = a.Exec(context.Background(), tool, args)

	if rec.tool == nil || rec.tool.Name != "subfinder" {
		t.Errorf("expected local.Exec called with 'subfinder'; got tool=%v", rec.tool)
	}
}

// TestAxiomBackend_MappedTool_InputFlagPositional asserts that for a tool
// with InputFlag="" (puredns), the last positional arg is used as input file
// in the axiom-scan invocation.
func TestAxiomBackend_MappedTool_InputFlagPositional(t *testing.T) {
	rec := &axiomRecorder{}
	cfg := axiomTestConfig(1)
	reg := backend.NewToolRegistry()
	a := backend.NewAxiomBackendWithLocal(cfg, reg, nil, rec)

	// puredns is in moduleMap → "puredns-resolve"; InputFlag="".
	tool := &backend.Tool{Name: "puredns", Path: "/usr/bin/puredns", InputFlag: ""}
	args := []string{"resolve", "/tmp/subs.txt"}
	_, _ = a.Exec(context.Background(), tool, args)

	// AxiomBackend must call local.Exec with axiom-scan as the tool;
	// and the first arg to axiom-scan must be the input file ("/tmp/subs.txt").
	if rec.tool == nil || rec.tool.Name != "axiom-scan" {
		t.Fatalf("expected local.Exec called with 'axiom-scan'; got tool=%v", rec.tool)
	}
	// Verify input file is in args.
	if len(rec.args) == 0 || rec.args[0] != "/tmp/subs.txt" {
		t.Errorf("axiom-scan args[0] = %q, want %q (input file)", safeFirst(rec.args), "/tmp/subs.txt")
	}
	// Verify -m puredns-resolve is in the args.
	if !argsContainSeq(rec.args, "-m", "puredns-resolve") {
		t.Errorf("axiom-scan args %v missing -m puredns-resolve", rec.args)
	}
}

// TestAxiomBackend_MappedTool_InputFlagFlag asserts that for a tool with
// InputFlag="-l" (dnsx), the arg immediately after "-l" is used as input file.
func TestAxiomBackend_MappedTool_InputFlagFlag(t *testing.T) {
	rec := &axiomRecorder{}
	cfg := axiomTestConfig(1)
	reg := backend.NewToolRegistry()
	a := backend.NewAxiomBackendWithLocal(cfg, reg, nil, rec)

	// dnsx is in moduleMap → "dnsx"; InputFlag="-l".
	tool := &backend.Tool{Name: "dnsx", Path: "/usr/bin/dnsx", InputFlag: "-l"}
	args := []string{"-l", "/tmp/resolved.txt", "-a", "-json"}
	_, _ = a.Exec(context.Background(), tool, args)

	if rec.tool == nil || rec.tool.Name != "axiom-scan" {
		t.Fatalf("expected local.Exec called with 'axiom-scan'; got tool=%v", rec.tool)
	}
	// The input file should be "/tmp/resolved.txt".
	if len(rec.args) == 0 || rec.args[0] != "/tmp/resolved.txt" {
		t.Errorf("axiom-scan args[0] = %q, want %q (input file from -l flag)", safeFirst(rec.args), "/tmp/resolved.txt")
	}
	if !argsContainSeq(rec.args, "-m", "dnsx") {
		t.Errorf("axiom-scan args %v missing -m dnsx", rec.args)
	}
}

// TestAxiomBackend_HealthCheck_ReturnsErrorOnFailure asserts HealthCheck returns
// non-nil when fleet probe fails.
func TestAxiomBackend_HealthCheck_ReturnsErrorOnFailure(t *testing.T) {
	rec := &axiomRecorder{execErr: errFleet}
	cfg := axiomTestConfig(1)
	reg := backend.NewToolRegistry()
	a := backend.NewAxiomBackendWithLocal(cfg, reg, nil, rec)

	err := a.HealthCheck(context.Background())
	if err == nil {
		t.Fatal("HealthCheck: expected non-nil error when fleet probe fails; got nil")
	}
}

// TestAxiomBackend_HealthCheck_AutoFixHostkey_TriggersRepair asserts that when
// the health-check probe returns "REMOTE HOST IDENTIFICATION HAS CHANGED"
// in stderr and AutoFixHostkey=true, HealthCheck issues a repair command
// (verified by seeing >= 2 Exec calls: probe + ssh-keygen -R).
func TestAxiomBackend_HealthCheck_AutoFixHostkey_TriggersRepair(t *testing.T) {
	rec := &hostKeyRecorder{}
	cfg := axiomTestConfig(1)
	cfg.Axiom.AutoFixHostkey = true
	reg := backend.NewToolRegistry()
	a := backend.NewAxiomBackendWithLocal(cfg, reg, nil, rec)

	_ = a.HealthCheck(context.Background())

	if rec.execCount < 2 {
		t.Errorf("AutoFixHostkey path: expected >= 2 Exec calls (probe + ssh-keygen); got %d", rec.execCount)
	}
}

// --- helpers ---

// axiomRecorder is a minimal Backend that records the last Exec call.
type axiomRecorder struct {
	tool    *backend.Tool
	args    []string
	execErr error
}

func (r *axiomRecorder) Exec(_ context.Context, t *backend.Tool, args []string) (*backend.Result, error) {
	r.tool = t
	r.args = args
	if r.execErr != nil {
		return nil, r.execErr
	}
	return &backend.Result{ExitCode: 0}, nil
}

func (r *axiomRecorder) Stream(_ context.Context, _ *backend.Tool, _ []string) (<-chan backend.Event, error) {
	ch := make(chan backend.Event)
	close(ch)
	return ch, nil
}

func (r *axiomRecorder) HealthCheck(_ context.Context) error { return nil }
func (r *axiomRecorder) Capacity() int                       { return 1 }

// hostKeyRecorder simulates the first Exec returning "REMOTE HOST IDENTIFICATION
// HAS CHANGED" in stderr so HealthCheck triggers repairKnownHosts.
type hostKeyRecorder struct {
	execCount int
}

func (h *hostKeyRecorder) Exec(_ context.Context, _ *backend.Tool, _ []string) (*backend.Result, error) {
	h.execCount++
	if h.execCount == 1 {
		return &backend.Result{
			Stderr:   []byte("REMOTE HOST IDENTIFICATION HAS CHANGED!\n"),
			ExitCode: 255,
		}, nil
	}
	return &backend.Result{ExitCode: 0}, nil
}

func (h *hostKeyRecorder) Stream(_ context.Context, _ *backend.Tool, _ []string) (<-chan backend.Event, error) {
	ch := make(chan backend.Event)
	close(ch)
	return ch, nil
}

func (h *hostKeyRecorder) HealthCheck(_ context.Context) error { return nil }
func (h *hostKeyRecorder) Capacity() int                       { return 1 }

// axiomTestConfig returns a minimal *config.Config with Axiom fields set.
func axiomTestConfig(fleetCount int) *config.Config {
	cfg := &config.Config{}
	cfg.Axiom.Enabled = true
	cfg.Axiom.FleetCount = fleetCount
	cfg.Axiom.FleetName = "test-fleet"
	return cfg
}

func safeFirst(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

func argsContainSeq(args []string, a, b string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == a && args[i+1] == b {
			return true
		}
	}
	return false
}

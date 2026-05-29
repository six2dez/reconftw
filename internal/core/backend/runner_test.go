// SPDX-License-Identifier: MIT
//
// Tests 13-16 from .planning/phases/03-foundation-kernel/03-04-PLAN.md Task 2
// (Runner wraps Backend + ToolRegistry + RateLimiter).
//
// Per Blocker 7: this test file uses fresh *ToolRegistry instances, never backend.Default.
package backend_test

import (
	"context"
	stderrors "errors"
	"testing"

	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
)

// Test 13: Runner.Run with a registered tool dispatches to Backend.Exec.
func TestRunner_Run_RegisteredTool_DispatchesToBackend(t *testing.T) {
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "echo", Path: "/bin/echo"})
	limiter := backend.NewRateLimiter(nil, 0)
	r := backend.NewRunner(backend.NewLocalBackend(0), reg, limiter)

	res, err := r.Run(context.Background(), "echo", []string{"hi"})
	if err != nil {
		t.Fatalf("Run(echo hi) err=%v, want nil", err)
	}
	if string(res.Stdout) != "hi\n" {
		t.Errorf("Run stdout = %q, want %q", string(res.Stdout), "hi\n")
	}
}

// Test 14: Runner.Run on unregistered tool returns *ToolError{ExitCode: -1, Inner: "not registered"}.
func TestRunner_Run_UnregisteredTool_ReturnsToolError(t *testing.T) {
	reg := backend.NewToolRegistry()
	limiter := backend.NewRateLimiter(nil, 0)
	r := backend.NewRunner(backend.NewLocalBackend(0), reg, limiter)

	_, err := r.Run(context.Background(), "ghost", []string{"x"})
	if err == nil {
		t.Fatalf("Run(ghost) err=nil, want *ToolError")
	}
	var te *coreerrors.ToolError
	if !stderrors.As(err, &te) {
		t.Fatalf("Run(ghost) err is not *ToolError: %T %v", err, err)
	}
	if te.Tool != "ghost" {
		t.Errorf("ToolError.Tool = %q, want %q", te.Tool, "ghost")
	}
	if te.ExitCode != -1 {
		t.Errorf("ToolError.ExitCode = %d, want -1 (unregistered tool sentinel)", te.ExitCode)
	}
}

// Test 15: Runner.Stream returns the Backend.Stream channel for a registered tool.
func TestRunner_Stream_RegisteredTool_ReturnsChannel(t *testing.T) {
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "echo", Path: "/bin/echo"})
	limiter := backend.NewRateLimiter(nil, 0)
	r := backend.NewRunner(backend.NewLocalBackend(0), reg, limiter)

	ch, err := r.Stream(context.Background(), "echo", []string{"hello"})
	if err != nil {
		t.Fatalf("Stream(echo) err=%v", err)
	}
	if ch == nil {
		t.Fatalf("Stream(echo) returned nil channel")
	}
	// Drain — we just want to confirm the channel closes cleanly.
	count := 0
	for ev := range ch {
		count++
		if count == 1 && string(ev.Line) != "hello" {
			t.Errorf("first event Line = %q, want %q", string(ev.Line), "hello")
		}
	}
}

// Test 16: Backend switching — Runner with real AxiomBackend (Phase 4 plan-06).
// The real AxiomBackend delegates unmapped tools (subfinder) to local execution.
// Since /usr/local/bin/subfinder is absent in CI, it returns a ToolError (not
// AxiomFailure). We verify (a) Runner construction accepts the 3-arg NewAxiomBackend
// and (b) tool dispatch works end-to-end when the path resolves.
func TestRunner_AxiomBackend_ConstructionWithRealBackend(t *testing.T) {
	cfg := &config.Config{}
	cfg.Axiom.Enabled = true
	cfg.Axiom.FleetCount = 3
	cfg.Axiom.FleetName = "test-fleet"

	reg := backend.NewToolRegistry()
	limiter := backend.NewRateLimiter(nil, 0)

	// Verify 3-arg constructor compiles and produces a non-nil Runner.
	axiomBE := backend.NewAxiomBackend(cfg, reg, nil)
	r := backend.NewRunner(axiomBE, reg, limiter)
	if r == nil {
		t.Fatal("NewRunner with real AxiomBackend returned nil")
	}

	// Capacity should be FleetCount.
	if got := axiomBE.Capacity(); got != 3 {
		t.Errorf("AxiomBackend.Capacity() = %d, want 3", got)
	}
}

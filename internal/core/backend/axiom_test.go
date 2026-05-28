// SPDX-License-Identifier: MIT
//
// Tests 2, 5, 12-15 from .planning/phases/03-foundation-kernel/03-04-PLAN.md Task 1.
// Asserts the AxiomBackend stub returns *AxiomFailure with the Operation field
// matching the method name (Blocker 6 — Stream MUST be "stream", not "exec").
package backend_test

import (
	"context"
	stderrors "errors"
	"testing"

	"github.com/six2dez/reconftw/internal/core/backend"
	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
)

// Test 2: AxiomBackend satisfies Backend at compile time.
var _ backend.Backend = (*backend.AxiomBackend)(nil)

// Test 5: AxiomBackend.Capacity() returns 0 (no fleet wired in Phase 3 stub).
func TestAxiomBackend_Capacity_ReturnsZero(t *testing.T) {
	a := backend.NewAxiomBackend()
	if got := a.Capacity(); got != 0 {
		t.Fatalf("AxiomBackend.Capacity() = %d, want 0", got)
	}
}

// Test 12: Exec returns *AxiomFailure with Operation == "exec".
func TestAxiomBackend_Exec_ReturnsAxiomFailureWithOperationExec(t *testing.T) {
	a := backend.NewAxiomBackend()
	res, err := a.Exec(context.Background(), &backend.Tool{Name: "subfinder"}, []string{"-d", "x.com"})
	if res != nil {
		t.Fatalf("Exec returned non-nil result on stub: %+v", res)
	}
	var af *coreerrors.AxiomFailure
	if !stderrors.As(err, &af) {
		t.Fatalf("Exec error is not *AxiomFailure: %T %v", err, err)
	}
	if af.Operation != "exec" {
		t.Errorf("Exec AxiomFailure.Operation = %q, want %q", af.Operation, "exec")
	}
	if !stderrors.Is(err, backend.ErrAxiomNotImplemented) {
		t.Errorf("Exec inner is not ErrAxiomNotImplemented: %v", err)
	}
}

// Test 13: Stream returns *AxiomFailure with Operation == "stream" (Blocker 6 fix).
// This is the bug — pre-Blocker-6, Stream returned Operation == "exec".
func TestAxiomBackend_Stream_ReturnsAxiomFailureWithOperationStream(t *testing.T) {
	a := backend.NewAxiomBackend()
	ch, err := a.Stream(context.Background(), &backend.Tool{Name: "nuclei"}, nil)
	if ch != nil {
		t.Fatalf("Stream returned non-nil channel on stub: %v", ch)
	}
	var af *coreerrors.AxiomFailure
	if !stderrors.As(err, &af) {
		t.Fatalf("Stream error is not *AxiomFailure: %T %v", err, err)
	}
	// THE Blocker 6 assertion: Operation must be the method name, not "exec".
	if af.Operation != "stream" {
		t.Errorf("Stream AxiomFailure.Operation = %q, want %q (Blocker 6)", af.Operation, "stream")
	}
}

// Test 14: HealthCheck returns *AxiomFailure with Operation == "healthcheck".
func TestAxiomBackend_HealthCheck_ReturnsAxiomFailureWithOperationHealthcheck(t *testing.T) {
	a := backend.NewAxiomBackend()
	err := a.HealthCheck(context.Background())
	var af *coreerrors.AxiomFailure
	if !stderrors.As(err, &af) {
		t.Fatalf("HealthCheck error is not *AxiomFailure: %T %v", err, err)
	}
	if af.Operation != "healthcheck" {
		t.Errorf("HealthCheck AxiomFailure.Operation = %q, want %q", af.Operation, "healthcheck")
	}
}

// Test 15: errors.Is(axiomErr, ErrAxiom) bridges through the AxiomFailure sentinel.
func TestAxiomBackend_AxiomFailure_BridgesToErrAxiomSentinel(t *testing.T) {
	a := backend.NewAxiomBackend()
	_, err := a.Exec(context.Background(), &backend.Tool{Name: "subfinder"}, nil)
	if !stderrors.Is(err, coreerrors.ErrAxiom) {
		t.Errorf("errors.Is(err, ErrAxiom) = false; want true (sentinel bridge broken)")
	}
}

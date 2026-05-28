// SPDX-License-Identifier: MIT
//
// AxiomBackend — compile-only stub per CONTEXT default (b) for Phase 3.
// All four Backend methods return *AxiomFailure with Operation matching the method name.
//
// BLOCKER 6 FIX: Stream returns Operation="stream", NOT "exec". This bug, if shipped,
// would produce misleading error messages in Phase 4 axiom-failover diagnostics.
//
// Phase 4 plan-XX swaps these stubs for the real axiom-fleet SSH-dispatch logic.
package backend

import (
	"context"
	"errors"

	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
)

// ErrAxiomNotImplemented is the inner error wrapped by every AxiomBackend stub.
// Phase 4 plan-XX deletes this sentinel when the real backend lands.
var ErrAxiomNotImplemented = errors.New("axiom backend not implemented (Phase 4)")

// AxiomBackend is a Phase 3 compile-only stub satisfying the Backend interface.
// Every method returns *coreerrors.AxiomFailure with Inner==ErrAxiomNotImplemented.
type AxiomBackend struct{}

// NewAxiomBackend constructs the zero-value stub.
func NewAxiomBackend() *AxiomBackend { return &AxiomBackend{} }

// Exec returns *AxiomFailure with Operation="exec".
func (a *AxiomBackend) Exec(_ context.Context, _ *Tool, _ []string) (*Result, error) {
	return nil, &coreerrors.AxiomFailure{Operation: "exec", Inner: ErrAxiomNotImplemented}
}

// Stream returns *AxiomFailure with Operation="stream" (Blocker 6 fix — was "exec").
func (a *AxiomBackend) Stream(_ context.Context, _ *Tool, _ []string) (<-chan Event, error) {
	return nil, &coreerrors.AxiomFailure{Operation: "stream", Inner: ErrAxiomNotImplemented}
}

// HealthCheck returns *AxiomFailure with Operation="healthcheck".
func (a *AxiomBackend) HealthCheck(_ context.Context) error {
	return &coreerrors.AxiomFailure{Operation: "healthcheck", Inner: ErrAxiomNotImplemented}
}

// Capacity returns 0 — no fleet wired in the Phase 3 stub.
func (a *AxiomBackend) Capacity() int { return 0 }

// runner_absent_test.go — the "never started" contract on Runner.Run/Stream.
//
// An unregistered tool, an absent binary and a rate-limiter abort are all
// dispatch failures: no process was created. task.ClassifyToolErr turns that
// into StatusSkipped + "tool absent", which is only right if the Runner marks
// every such error. These tests pin both the typed sentinel and the flag.
package backend_test

import (
	"context"
	stderrors "errors"
	"testing"

	"github.com/six2dez/reconftw/internal/core/backend"
	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
)

func TestRunnerUnregisteredToolIsTypedNeverStarted(t *testing.T) {
	reg := backend.NewToolRegistry()
	r := backend.NewRunner(backend.NewLocalBackend(0), reg, nil)

	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"Run", func() error { _, err := r.Run(context.Background(), "ghost", nil); return err }},
		{"Stream", func() error { _, err := r.Stream(context.Background(), "ghost", nil); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			if err == nil {
				t.Fatal("unregistered tool returned nil error")
			}
			if !stderrors.Is(err, backend.ErrToolNotRegistered) {
				t.Errorf("errors.Is(err, ErrToolNotRegistered) = false for %v", err)
			}
			if !coreerrors.IsDispatchFailure(err) {
				t.Errorf("IsDispatchFailure = false — the Runner must mark an unregistered tool as never started: %v", err)
			}
			if !stderrors.Is(err, coreerrors.ErrTool) {
				t.Errorf("errors.Is(err, ErrTool) = false — ErrDispatch narrows the category, it must not leave it")
			}
		})
	}
}

func TestRunnerAbsentBinaryIsNeverStartedNotExitNonZero(t *testing.T) {
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "absent"}) // registered, Path == "" (Discover found nothing)
	r := backend.NewRunner(backend.NewLocalBackend(0), reg, nil)

	_, err := r.Run(context.Background(), "absent", []string{"-h"})
	if err == nil {
		t.Fatal("absent binary returned nil error")
	}
	if !coreerrors.IsDispatchFailure(err) {
		t.Fatalf("absent binary must be a dispatch failure (never started), got %v", err)
	}
	if stderrors.Is(err, backend.ErrToolNotRegistered) {
		t.Errorf("an absent binary is REGISTERED; it must not carry ErrToolNotRegistered: %v", err)
	}
}

func TestRunnerExitNonZeroIsNotNeverStarted(t *testing.T) {
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "false", Path: "/usr/bin/false"})
	r := backend.NewRunner(backend.NewLocalBackend(0), reg, nil)

	_, err := r.Run(context.Background(), "false", nil)
	if err == nil {
		t.Fatal("/usr/bin/false returned nil error")
	}
	if coreerrors.IsDispatchFailure(err) {
		t.Errorf("a tool that RAN and exited non-zero must not be labelled never-started: %v", err)
	}
}

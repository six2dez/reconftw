// SPDX-License-Identifier: MIT
//
// axiom-scan's exit status is not a result signal — the output file is.
//
// Ax's axiom-scan has no `set -e`; its clean_up() ends `stty sane; tput init;
// exit`, so the script's status is whatever `tput init` returned, and with no
// TTY (how AxiomBackend runs it) that is non-zero on every SUCCESSFUL scan. On
// the 2026-09-04 fleet run puredns, dnsx and tlsx each completed on the fleet in
// ~52s with real results in their -o files; every one was classified
// "axiom-scan error", the files were never read, each tool re-ran locally for
// ~9 minutes, and the fleet was abandoned after two such "failures".

package backend_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/backend"
	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
)

// axiomNonZeroFake behaves like the real axiom-scan under no TTY: it writes the
// fleet's merged results to the -o file (when fixture is non-nil) and then exits
// non-zero because `tput init` failed.
type axiomNonZeroFake struct {
	fixture      []byte // nil → write no output file at all
	calls        []string
	cancelCaller bool // simulate the scan cancelling this dispatch mid-run
	cancel       context.CancelFunc
}

func (f *axiomNonZeroFake) Exec(_ context.Context, t *backend.Tool, args []string) (*backend.Result, error) {
	f.calls = append(f.calls, t.Name)
	if t.Name != "axiom-scan" {
		return &backend.Result{Stdout: []byte("local result\n")}, nil // the failover/local leg
	}
	if f.fixture != nil {
		for i, a := range args {
			if a == "-o" && i+1 < len(args) {
				_ = os.WriteFile(args[i+1], f.fixture, 0o644)
			}
		}
	}
	if f.cancelCaller && f.cancel != nil {
		f.cancel() // the stage failed elsewhere; our process was SIGKILLed
		return nil, &coreerrors.ToolError{Tool: "axiom-scan", ExitCode: -1, Stderr: "signal: killed"}
	}
	return nil, &coreerrors.ToolError{Tool: "axiom-scan", ExitCode: 1, Stderr: "tput: No value for $TERM and no -T specified"}
}

func (f *axiomNonZeroFake) ExecEnv(ctx context.Context, t *backend.Tool, args []string, _ []string) (*backend.Result, error) {
	return f.Exec(ctx, t, args)
}

func (f *axiomNonZeroFake) Stream(_ context.Context, _ *backend.Tool, _ []string) (<-chan backend.Event, error) {
	ch := make(chan backend.Event)
	close(ch)
	return ch, nil
}

func (f *axiomNonZeroFake) StreamEnv(ctx context.Context, t *backend.Tool, args []string, _ []string) (<-chan backend.Event, error) {
	return f.Stream(ctx, t, args)
}

func (f *axiomNonZeroFake) ExecOpts(ctx context.Context, t *backend.Tool, args []string, _ backend.ExecOptions) (*backend.Result, error) {
	return f.Exec(ctx, t, args)
}

func (f *axiomNonZeroFake) StreamOpts(ctx context.Context, t *backend.Tool, args []string, _ backend.ExecOptions) (<-chan backend.Event, error) {
	return f.Stream(ctx, t, args)
}
func (f *axiomNonZeroFake) HealthCheck(_ context.Context) error { return nil }
func (f *axiomNonZeroFake) Capacity() int                       { return 1 }

func dispatchInput(t *testing.T) string {
	t.Helper()
	in := filepath.Join(t.TempDir(), "passive.merged.txt")
	if err := os.WriteFile(in, []byte("a.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return in
}

// The fleet's results must be USED when the -o file exists, whatever the exit status.
func TestAxiomExecUsesOutputFileDespiteNonZeroExit(t *testing.T) {
	fixture := []byte("backoffice.example.com\njobs.example.com\n")
	fake := &axiomNonZeroFake{fixture: fixture}
	a := backend.NewAxiomBackendWithLocal(axiomTestConfig(1), backend.NewToolRegistry(), nil, fake)

	res, err := a.Exec(context.Background(), &backend.Tool{Name: "puredns"}, []string{"resolve", dispatchInput(t)})
	if err != nil {
		t.Fatalf("Exec returned %v: the fleet completed and wrote its results, and they were thrown away — "+
			"this is the 2026-09-04 run, where every dispatch was 'axiom-scan error' with data on disk", err)
	}
	if string(res.Stdout) != string(fixture) {
		t.Errorf("stdout = %q, want the fleet's output file verbatim", res.Stdout)
	}
	dispatched, local := a.DistributionSummary()
	if dispatched["puredns"] != 1 {
		t.Errorf("dispatch not credited to the fleet: %v", dispatched)
	}
	if _, wrong := local["puredns"]; wrong {
		t.Errorf("a successful dispatch was recorded as local: %v", local)
	}
}

// Two of those in a row must NOT abandon the fleet — that is exactly how a healthy
// fleet was abandoned after 12 minutes on 2026-09-04.
func TestAxiomHealthyFleetIsNotAbandonedByCosmeticExitStatus(t *testing.T) {
	fake := &axiomNonZeroFake{fixture: []byte("x.example.com\n")}
	a := backend.NewAxiomBackendWithLocal(axiomTestConfig(1), backend.NewToolRegistry(), nil, fake)
	for i := 0; i < 3; i++ {
		if _, err := a.Exec(context.Background(), &backend.Tool{Name: "tlsx", InputFlag: "-l"}, []string{"-l", dispatchInput(t), "-san"}); err != nil {
			t.Fatalf("dispatch %d: %v", i, err)
		}
	}
	var axiomCalls int
	for _, c := range fake.calls {
		if c == "axiom-scan" {
			axiomCalls++
		}
	}
	if axiomCalls != 3 {
		t.Errorf("axiom-scan was invoked %d times of 3 — the fleet was abandoned on cosmetic exit statuses", axiomCalls)
	}
}

// The other direction is preserved: non-zero exit AND no output file is still a
// failure that fails over locally — and now it is recorded as such.
func TestAxiomExecStillFailsWithoutOutputFile(t *testing.T) {
	fake := &axiomNonZeroFake{fixture: nil}
	a := backend.NewAxiomBackendWithLocal(axiomTestConfig(1), backend.NewToolRegistry(), nil, fake)

	_, err := a.Exec(context.Background(), &backend.Tool{Name: "dnsx", InputFlag: "-l"}, []string{"-l", dispatchInput(t)})
	var axErr *coreerrors.AxiomFailure
	if err == nil || !errorsAs(err, &axErr) {
		t.Fatalf("want *AxiomFailure for non-zero exit with no output file, got %v", err)
	}
	_, local := a.DistributionSummary()
	reason, ok := local["dnsx"]
	if !ok {
		t.Fatal("a failed dispatch left no ledger entry — the end-of-run summary would read " +
			"'every tool ran locally' with an EMPTY list, as it did on 2026-09-04")
	}
	if !strings.Contains(reason, "failover") {
		t.Errorf("reason = %q, want it to say the tool was re-run locally by failover", reason)
	}
}

func errorsAs(err error, target **coreerrors.AxiomFailure) bool {
	for e := err; e != nil; {
		if ax, ok := e.(*coreerrors.AxiomFailure); ok {
			*target = ax
			return true
		}
		u, ok := e.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		e = u.Unwrap()
	}
	return false
}

// A dispatch WE killed (caller's context cancelled) is not a completed scan even
// if a file is on disk: merge_output may have been mid-write when the signal
// landed. The second dnsx of the 2026-09-05 run ended `signal: killed` with a
// file present and was wrongly accepted.
func TestAxiomExecDoesNotUseOutputFileOfADispatchItCancelled(t *testing.T) {
	fake := &axiomNonZeroFake{fixture: []byte("partial\n"), cancelCaller: true}
	a := backend.NewAxiomBackendWithLocal(axiomTestConfig(1), backend.NewToolRegistry(), nil, fake)
	ctx, cancel := context.WithCancel(context.Background())
	fake.cancel = cancel
	_, err := a.Exec(ctx, &backend.Tool{Name: "dnsx", InputFlag: "-l"}, []string{"-l", dispatchInput(t)})
	if err == nil {
		t.Fatal("a dispatch killed by the caller's cancellation was accepted as a completed scan")
	}
}

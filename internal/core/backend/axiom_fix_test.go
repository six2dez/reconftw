// axiom_fix_test.go — regression guards for the 3 --axiom distribution bugs found by
// live testing on reconbox3 (2026-08): every distributed tool silently yielded nothing.
//
//	RC-A: AxiomBackend.Exec never read axiom-scan's `-o <outFile>` back → results lost.
//	RC-B: extractInputFile returned the trailing flag ("--quiet") instead of the input.
//	RC-C: puredns bruteforce was dispatched to the resolve module (wrong op) → 0 brute.
//
// Reuses axiomRecorder / axiomTestConfig / safeFirst from axiom_test.go.
package backend_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/six2dez/reconftw/internal/core/backend"
)

// axiomOutFake is a fake local backend that behaves like the real `axiom-scan -o`:
// it writes results to the -o output FILE and returns only progress noise on stdout.
type axiomOutFake struct {
	fixture []byte
	gotArgs []string
}

func (f *axiomOutFake) Exec(_ context.Context, _ *backend.Tool, args []string) (*backend.Result, error) {
	f.gotArgs = args
	for i, a := range args {
		if a == "-o" && i+1 < len(args) {
			_ = os.WriteFile(args[i+1], f.fixture, 0o644)
		}
	}
	return &backend.Result{Stdout: []byte("axiom-scan progress noise\n"), ExitCode: 0}, nil
}

func (f *axiomOutFake) ExecEnv(ctx context.Context, t *backend.Tool, args []string, _ []string) (*backend.Result, error) {
	return f.Exec(ctx, t, args)
}

func (f *axiomOutFake) Stream(_ context.Context, _ *backend.Tool, _ []string) (<-chan backend.Event, error) {
	ch := make(chan backend.Event)
	close(ch)
	return ch, nil
}

func (f *axiomOutFake) StreamEnv(ctx context.Context, t *backend.Tool, args []string, _ []string) (<-chan backend.Event, error) {
	return f.Stream(ctx, t, args)
}
func (f *axiomOutFake) HealthCheck(_ context.Context) error { return nil }
func (f *axiomOutFake) Capacity() int                       { return 1 }

// RC-A: Exec must surface the axiom-scan OUTPUT FILE content, not its stdout noise.
func TestAxiomExecReadsOutputFileBack(t *testing.T) {
	dir := t.TempDir()
	inputFile := filepath.Join(dir, "passive.merged.txt")
	if err := os.WriteFile(inputFile, []byte("a.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fixture := []byte("resolved1.example.com\nresolved2.example.com\n")
	fake := &axiomOutFake{fixture: fixture}
	a := backend.NewAxiomBackendWithLocal(axiomTestConfig(1), backend.NewToolRegistry(), nil, fake)
	tool := &backend.Tool{Name: "puredns", Path: "/usr/bin/puredns", InputFlag: ""}

	res, err := a.Exec(context.Background(), tool, []string{"resolve", inputFile, "--quiet"})
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if string(res.Stdout) != string(fixture) {
		t.Errorf("Exec res.Stdout = %q, want the -o output-file content %q\n"+
			"(RC-A: axiom-scan output file was never read back → every distributed tool yielded nothing)",
			res.Stdout, fixture)
	}
	leftovers, _ := filepath.Glob(inputFile + ".axiom.*.out")
	if len(leftovers) != 0 {
		t.Errorf("axiom output temp files were not cleaned up: %v", leftovers)
	}
}

// RC-B: for puredns's real arg vector the input file is positional #2 (before the
// flags), NOT the last arg — extractInputFile must not return the trailing "--quiet".
func TestAxiomExecInputFileIsNotTrailingFlag(t *testing.T) {
	rec := &axiomRecorder{}
	a := backend.NewAxiomBackendWithLocal(axiomTestConfig(1), backend.NewToolRegistry(), nil, rec)
	tool := &backend.Tool{Name: "puredns", Path: "/usr/bin/puredns", InputFlag: ""}
	// The REAL SubActiveTask.Run vector: input file is arg #2, "--quiet" is last.
	args := []string{
		"resolve", "/tmp/passive.merged.txt", "-r", "/tmp/res.txt",
		"--wildcard-tests", "50", "-rt", "/tmp/rt.txt", "--quiet",
	}
	_, _ = a.Exec(context.Background(), tool, args)

	if rec.tool == nil || rec.tool.Name != "axiom-scan" {
		t.Fatalf("expected axiom-scan dispatch; got tool=%v", rec.tool)
	}
	if len(rec.args) == 0 || rec.args[0] != "/tmp/passive.merged.txt" {
		t.Errorf("axiom-scan input arg = %q, want /tmp/passive.merged.txt\n"+
			"(RC-B: the old last-arg heuristic picked the trailing --quiet flag)", safeFirst(rec.args))
	}
}

// RC-C: puredns bruteforce has no axiom module → must run LOCALLY (original puredns
// tool passed through), never dispatched to axiom-scan -m puredns-resolve.
func TestAxiomBruteforceRunsLocal(t *testing.T) {
	rec := &axiomRecorder{}
	a := backend.NewAxiomBackendWithLocal(axiomTestConfig(1), backend.NewToolRegistry(), nil, rec)
	tool := &backend.Tool{Name: "puredns", Path: "/usr/bin/puredns", InputFlag: ""}
	_, _ = a.Exec(context.Background(), tool, []string{"bruteforce", "/tmp/words.txt", "-d", "example.com", "--quiet"})

	if rec.tool == nil || rec.tool.Name != "puredns" {
		t.Errorf("bruteforce dispatched to %v, want local passthrough of 'puredns'\n"+
			"(RC-C: -m puredns-resolve on a bruteforce op silently yields 0 candidates)", rec.tool)
	}
}

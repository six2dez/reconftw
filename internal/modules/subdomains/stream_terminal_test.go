// stream_terminal_test.go — F6 (phase 15, plan 15-13 Task 2) acceptance gate 5
// for the subdomains package, asserted in BOTH directions.
//
// This package is where getting the direction wrong is most expensive.
// internal/core/scheduler/policy.go gives the `subdomains` module
// PolicyFailFast, so escalating a DISPATCH failure ("the optional binary is not
// installed") into task.StatusErrored would abort the entire subdomains spine on
// any host with an incomplete toolchain. Only a stream that actually STARTED and
// then ended badly may become StatusErrored.
package subdomains_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

// terminalStreamBackend emits lines and then a terminal Event.Err, modelling a
// tool that wrote partial output and exited non-zero. Stream() itself succeeds:
// the tool WAS dispatched.
type terminalStreamBackend struct {
	lines   []string
	termErr error
}

func (b *terminalStreamBackend) Exec(_ context.Context, _ *backend.Tool, _ []string) (*backend.Result, error) {
	return &backend.Result{ExitCode: 0}, nil
}

func (b *terminalStreamBackend) ExecEnv(ctx context.Context, t *backend.Tool, args, _ []string) (*backend.Result, error) {
	return b.Exec(ctx, t, args)
}

func (b *terminalStreamBackend) Stream(_ context.Context, _ *backend.Tool, _ []string) (<-chan backend.Event, error) {
	ch := make(chan backend.Event, len(b.lines)+1)
	for _, l := range b.lines {
		ch <- backend.Event{Line: []byte(l)}
	}
	if b.termErr != nil {
		ch <- backend.Event{Err: b.termErr}
	}
	close(ch)
	return ch, nil
}

func (b *terminalStreamBackend) StreamEnv(ctx context.Context, t *backend.Tool, args, _ []string) (<-chan backend.Event, error) {
	return b.Stream(ctx, t, args)
}

func (b *terminalStreamBackend) HealthCheck(_ context.Context) error { return nil }
func (b *terminalStreamBackend) Capacity() int                       { return 1 }

func newStreamApp(t *testing.T, workDir string, be backend.Backend, tools ...string) *appctx.AppContext {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(workDir, "inputs"), 0o755); err != nil {
		t.Fatalf("mkdir inputs: %v", err)
	}
	reg := backend.NewToolRegistry()
	for _, name := range tools {
		reg.Register(&backend.Tool{Name: name})
	}
	cfg := &config.Config{}
	cfg.Subdomains.Passive.Enabled = true
	cfg.Subdomains.Brute.Enabled = true
	cfg.Subdomains.DNSResolve.PurednsWildcardtestLimit = 100
	cfg.Subdomains.DNSResolve.PurednsWildcardbatchLimit = 1000000
	cfg.Subdomains.DNSResolve.PurednsPublicLimit = 5000
	cfg.Subdomains.DNSResolve.PurednsTrustedLimit = 5000
	return &appctx.AppContext{
		Tools:  backend.NewRunner(be, reg, nil),
		Tree:   &mockTree{},
		Cfg:    cfg,
		Target: &appctx.Target{Domain: "example.com", WorkDir: workDir},
	}
}

// ---------------------------------------------------------------------------
// TERMINAL — gate 5.
// ---------------------------------------------------------------------------

// TestSubActiveExitSevenErrorsAndStagesNothing drives subdomains.active (puredns
// via runStreamTask) with a stub that emits one resolved host and then exits 7.
//
// The staging file is seeded with a PREVIOUS run's hostname first: a run that
// ignored the terminal error would overwrite it with the single partial host and
// report success, silently shrinking the resolved corpus every later stage
// builds on. The correct behaviour is StatusErrored with the staging untouched —
// this run cannot vouch for a replacement.
func TestSubActiveExitSevenErrorsAndStagesNothing(t *testing.T) {
	workDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(workDir, "inputs"), 0o755); err != nil {
		t.Fatalf("mkdir inputs: %v", err)
	}
	staging := filepath.Join(workDir, "inputs", "resolved.puredns.txt")
	if err := os.WriteFile(filepath.Join(workDir, "inputs", "passive.merged.txt"),
		[]byte("api.example.com\nmail.example.com\n"), 0o644); err != nil {
		t.Fatalf("seed passive.merged.txt: %v", err)
	}
	if err := os.WriteFile(staging, []byte("previous.example.com\n"), 0o644); err != nil {
		t.Fatalf("seed staging: %v", err)
	}

	be := &terminalStreamBackend{
		lines:   []string{"api.example.com"},
		termErr: errors.New("exit status 7"),
	}
	app := newStreamApp(t, workDir, be, "puredns")

	res, err := lookupSubTask(t, "subdomains.active").Run(context.Background(), app)
	if res.Status != task.StatusErrored {
		t.Errorf("status = %q, want errored (puredns ran and exited 7)", res.Status)
	}
	if err == nil {
		t.Error("a terminal stream error must be returned, not swallowed")
	}
	got, rErr := os.ReadFile(staging) //nolint:gosec // test-controlled temp path
	if rErr != nil {
		t.Fatalf("staging must be left untouched after a terminal error: %v", rErr)
	}
	if string(got) != "previous.example.com\n" {
		t.Errorf("a PARTIAL resolve must not be staged as this run's result, got: %q", string(got))
	}
}

// TestSubBruteExitSevenErrorsAndStagesNothing is the same assertion for
// subdomains.brute, which owns its own accumulator loop.
func TestSubBruteExitSevenErrorsAndStagesNothing(t *testing.T) {
	workDir := t.TempDir()
	wordlist := filepath.Join(workDir, "subs.txt")
	if err := os.WriteFile(wordlist, []byte("api\nmail\n"), 0o644); err != nil {
		t.Fatalf("seed wordlist: %v", err)
	}
	resolvers := filepath.Join(workDir, "resolvers.txt")
	if err := os.WriteFile(resolvers, []byte("1.1.1.1\n"), 0o644); err != nil {
		t.Fatalf("seed resolvers: %v", err)
	}

	be := &terminalStreamBackend{
		lines:   []string{"api.example.com"},
		termErr: errors.New("exit status 7"),
	}
	app := newStreamApp(t, workDir, be, "puredns")
	app.Cfg.Paths.SubsWordlist = wordlist
	app.Cfg.Paths.Resolvers = resolvers

	res, err := lookupSubTask(t, "subdomains.brute").Run(context.Background(), app)
	if res.Status == task.StatusSkipped {
		t.Skip("brute skipped before reaching the stream (wordlist/resolver gate) — " +
			"the terminal-error path is covered by TestSubActiveExitSevenErrorsAndStagesNothing")
	}
	if res.Status != task.StatusErrored {
		t.Errorf("status = %q, want errored (puredns ran and exited 7)", res.Status)
	}
	if err == nil {
		t.Error("a terminal stream error must be returned, not swallowed")
	}
	staging := filepath.Join(workDir, "inputs", "resolved.brute.txt")
	if _, sErr := os.Stat(staging); !os.IsNotExist(sErr) {
		body, _ := os.ReadFile(staging) //nolint:gosec // test-controlled temp path
		t.Errorf("a PARTIAL bruteforce must not be staged, but %s was written: %q",
			staging, string(body))
	}
}

// ---------------------------------------------------------------------------
// DISPATCH — the over-escalation guard. THIS IS THE ONE THAT MATTERS MOST.
// ---------------------------------------------------------------------------

// TestSubdomainsPassiveAbsentToolNotEscalated is the passive-class absent-tool
// guard.
//
// A CORRECTION TO THE PREMISE, verified on the tree rather than assumed. Every
// task in this package returns Module() == "subdomains", which policyFor maps to
// PolicyFailFast — but Task.Module() is NOT what selects the policy. The
// scheduler keys off the STAGE-GROUP label passed to RunStage
// (internal/core/scheduler/scheduler.go: policyFor(module, …) where module is
// the caller's argument), and internal/mcp/handlers/composite.go runs
// subdomains.passive.* under the group label "subdomains.passive", which
// policyFor maps to PolicyBestEffort. The only PolicyFailFast group is
// "subs-resolve" (composite.go), holding subdomains.{active,tls,noerror,dns,
// srv,brute,resolvers.*}.
//
// So a passive source is best-effort in production, and its PRE-EXISTING
// StatusErrored on an absent binary — which comes from app.Tools.Run, not from
// any stream — is tolerated. What this plan must guarantee is narrower and is
// what is asserted here: the absent-tool outcome is still the DISPATCH error and
// was NOT converted into a terminal-stream error by the F6 migration.
func TestSubdomainsPassiveAbsentToolNotEscalated(t *testing.T) {
	absent := errors.New("executable file not found in $PATH")

	for _, taskName := range []string{
		"subdomains.passive.subfinder",
		"subdomains.passive.crt",
	} {
		t.Run(taskName, func(t *testing.T) {
			workDir := t.TempDir()
			be := &erroringBackend{err: absent}
			app := newStreamApp(t, workDir, be, "subfinder", "crt")

			_, err := lookupSubTask(t, taskName).Run(context.Background(), app)
			if err != nil && strings.Contains(err.Error(), "tool stream ended badly") {
				t.Errorf("%s: an ABSENT tool was reported as a terminal stream failure — "+
					"the F6 migration must never convert a dispatch error into one: %v",
					taskName, err)
			}
			// No staging may be produced either way: the source never ran.
			staging := filepath.Join(workDir, "inputs",
				"passive."+map[string]string{
					"subdomains.passive.subfinder": "subfinder",
					"subdomains.passive.crt":       "crt",
				}[taskName]+".txt")
			if _, sErr := os.Stat(staging); !os.IsNotExist(sErr) {
				t.Errorf("%s: a source that never ran must not write staging at %s",
					taskName, staging)
			}
		})
	}
}

// TestSubActiveAbsentToolStaysNonErrored is THE fail-fast guard that matters.
//
// subdomains.active runs in the "subs-resolve" stage group, the ONLY
// PolicyFailFast group in the subdomains pipeline (internal/mcp/handlers/
// composite.go). An absent puredns must keep going through degradeResolveTool's
// CONTINUE_ON_TOOL_ERROR degrade and must NOT be escalated by this plan's
// terminal-error handling — otherwise every host without puredns aborts its
// whole subdomain spine.
func TestSubActiveAbsentToolStaysNonErrored(t *testing.T) {
	workDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(workDir, "inputs"), 0o755); err != nil {
		t.Fatalf("mkdir inputs: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "inputs", "passive.merged.txt"),
		[]byte("api.example.com\n"), 0o644); err != nil {
		t.Fatalf("seed passive.merged.txt: %v", err)
	}

	be := &erroringBackend{err: errors.New("puredns: executable file not found in $PATH")}
	app := newStreamApp(t, workDir, be, "puredns")

	res, err := lookupSubTask(t, "subdomains.active").Run(context.Background(), app)
	if res.Status == task.StatusErrored {
		t.Errorf("a missing puredns must not fail subdomains.active — it runs in the "+
			"PolicyFailFast subs-resolve group, so this would abort the whole spine; "+
			"status = %q, err = %v", res.Status, err)
	}
	if err != nil && strings.Contains(err.Error(), "tool stream ended badly") {
		t.Errorf("an ABSENT tool was reported as a terminal stream failure: %v", err)
	}
}

func lookupSubTask(t *testing.T, name string) task.Task {
	t.Helper()
	tsk, ok := task.Default.Lookup(name)
	if !ok {
		t.Fatalf("%s not registered", name)
	}
	return tsk
}

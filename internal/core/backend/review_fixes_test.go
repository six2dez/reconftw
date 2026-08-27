// review_fixes_test.go — regressions for the blockers the 18-06 code review and
// the phase-18 verification found AFTER all six plans reported complete.
//
// Every test here was run against the UNFIXED code first and observed to fail;
// the failure it reproduces is quoted in its own doc comment. A guard that has
// never been seen to fail is not a guard — the rule this phase exists to enforce.
package backend

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
)

// ---------------------------------------------------------------------------
// CR-02 — a capability refusal is not evidence of an unhealthy fleet.
// ---------------------------------------------------------------------------

// TestUnmappedToolWithOptionsDoesNotTripTheKillSwitch pins the CR-02 fix.
//
// AxiomBackend.ExecOpts used to refuse ANY non-zero ExecOptions BEFORE consulting
// moduleMap. For a tool with no axiom module — one Exec would have delegated
// straight to a.local and returned success — that manufactured an *AxiomFailure,
// which FailoverBackend counts as a fleet failure. Three of them trip killSwitch
// (Threshold defaults to 3) and the fleet is abandoned for the rest of the scan
// with nothing surfaced to the operator.
//
// 18-04/18-05 put ten option-carrying dispatches on this path, two of which
// iterate per host or per repo, so three in a row is the NORMAL path of a --vps
// run, not a corner case.
//
// Observed before the fix:
//
//	KILL SWITCH TRIPPED after 3 stdin dispatches — axiom abandoned for the rest of the run
func TestUnmappedToolWithOptionsDoesNotTripTheKillSwitch(t *testing.T) {
	local := &optsRecordingBackend{}
	// An AxiomBackend with a real local leg and an EMPTY moduleMap: every tool is
	// unmapped, exactly like Gxss, mantra, hakoriginfinder and the rest of the
	// cohort 18-04/18-05 brought home.
	axiom := &AxiomBackend{moduleMap: map[string]string{}, local: local}
	f := &FailoverBackend{Primary: axiom, Fallback: &optsRecordingBackend{}, Threshold: 3}

	payload := []byte("candidate-urls")
	for i := 0; i < 5; i++ {
		if _, err := f.ExecOpts(context.Background(), &Tool{Name: "Gxss"}, nil,
			ExecOptions{Stdin: payload}); err != nil {
			t.Fatalf("dispatch %d returned an error: %v", i, err)
		}
	}

	if f.isKillSwitched() {
		t.Fatal("KILL SWITCH TRIPPED by stdin dispatches of an UNMAPPED tool — the fleet " +
			"is abandoned for the rest of the run because a capability refusal was " +
			"counted as evidence the fleet is unhealthy (CR-02)")
	}
	if !local.called {
		t.Fatal("the local leg was never reached — an unmapped tool must be served " +
			"locally WITH its options, exactly as Exec's fallback arm does")
	}
	if string(local.got.Stdin) != string(payload) {
		t.Errorf("the local leg lost the stdin bytes:\n got = %q\nwant = %q",
			local.got.Stdin, payload)
	}
}

// TestMappedToolWithOptionsStillRefuses pins the OTHER half — the T-18-01-05
// contract the CR-02 fix must not weaken. A tool that genuinely WOULD go to the
// fleet must still refuse loudly with a typed *AxiomFailure so FailoverBackend
// engages the local leg with the stdin intact, rather than running on the fleet
// with an empty standard input and reporting a clean zero-finding success.
func TestMappedToolWithOptionsStillRefuses(t *testing.T) {
	axiom := &AxiomBackend{
		moduleMap: map[string]string{"puredns": "puredns-resolve"},
		local:     &optsRecordingBackend{},
	}

	// A RESOLVABLE INPUT FILE is part of being fleet-bound. Exec falls back locally
	// when extractInputFile returns "" (V-02), and routesToFleet mirrors that, so a
	// mapped tool dispatched with no input file is NOT fleet-bound and correctly
	// does not refuse. Passing args here keeps this test on the path it names.
	_, err := axiom.ExecOpts(context.Background(),
		&Tool{Name: "puredns", InputFlag: "-l"},
		[]string{"-l", "/tmp/resolvable-input.txt"},
		ExecOptions{Stdin: []byte("x")})
	if err == nil {
		t.Fatal("a FLEET-BOUND tool carrying stdin was accepted — the stdin would be " +
			"silently dropped and the tool run with empty input (T-18-01-05)")
	}
	var axErr *coreerrors.AxiomFailure
	if !errors.As(err, &axErr) {
		t.Fatalf("error is %T, want *coreerrors.AxiomFailure — FailoverBackend keys on "+
			"that type, so a generic error means the local leg never engages", err)
	}
}

// TestMappedToolCapabilityRefusalDoesNotTripTheKillSwitch pins the distinction
// between "this fleet is unhealthy" and "this fleet transport cannot carry
// stdin". The latter must still fall back locally, but it is not evidence that
// later option-free tools should abandon the fleet.
func TestMappedToolCapabilityRefusalDoesNotTripTheKillSwitch(t *testing.T) {
	primaryLocal := &optsRecordingBackend{}
	fallback := &optsRecordingBackend{}
	axiom := &AxiomBackend{
		moduleMap: map[string]string{"puredns": "puredns-resolve"},
		local:     primaryLocal,
	}
	f := &FailoverBackend{Primary: axiom, Fallback: fallback, Threshold: 3}
	tool := &Tool{Name: "puredns", InputFlag: "-l"}

	for i := 0; i < 5; i++ {
		if _, err := f.ExecOpts(context.Background(), tool,
			[]string{"-l", "/tmp/resolvable-input.txt"},
			ExecOptions{Stdin: []byte("must-run-locally")}); err != nil {
			t.Fatalf("dispatch %d returned an error: %v", i, err)
		}
	}

	if f.isKillSwitched() {
		t.Fatal("KILL SWITCH TRIPPED after capability refusals — unsupported stdin was counted as fleet unhealthiness")
	}
	if !fallback.called {
		t.Fatal("the local fallback leg was never reached")
	}
}

func TestMappedToolStreamCapabilityRefusalDoesNotTripTheKillSwitch(t *testing.T) {
	primaryLocal := &optsRecordingBackend{}
	fallback := &optsRecordingBackend{}
	axiom := &AxiomBackend{
		moduleMap: map[string]string{"puredns": "puredns-resolve"},
		local:     primaryLocal,
	}
	f := &FailoverBackend{Primary: axiom, Fallback: fallback, Threshold: 3}
	tool := &Tool{Name: "puredns", InputFlag: "-l"}

	for i := 0; i < 5; i++ {
		ch, err := f.StreamOpts(context.Background(), tool,
			[]string{"-l", "/tmp/resolvable-input.txt"},
			ExecOptions{Stdin: []byte("must-run-locally")})
		if err != nil {
			t.Fatalf("dispatch %d returned an error: %v", i, err)
		}
		for range ch {
		}
	}

	if f.isKillSwitched() {
		t.Fatal("KILL SWITCH TRIPPED after streaming capability refusals")
	}
	if !fallback.called {
		t.Fatal("the local streaming fallback leg was never reached")
	}
}

type partialFailingStreamBackend struct {
	optsRecordingBackend
	stream <-chan Event
}

func (b *partialFailingStreamBackend) StreamOpts(context.Context, *Tool, []string, ExecOptions) (<-chan Event, error) {
	return b.stream, &coreerrors.AxiomFailure{Operation: "stream_opts", Inner: errors.New("fleet unreachable")}
}

func TestStreamDispatchFailureCountsOnceWithPartialChannel(t *testing.T) {
	partial := make(chan Event)
	drained := make(chan struct{})
	go func() {
		partial <- Event{Err: errors.New("terminal fleet error")}
		partial <- Event{}
		close(partial)
		close(drained)
	}()

	f := &FailoverBackend{
		Primary:   &partialFailingStreamBackend{stream: partial},
		Fallback:  &optsRecordingBackend{},
		Threshold: 2,
	}
	ch, err := f.StreamOpts(context.Background(), &Tool{Name: "puredns"}, nil, ExecOptions{})
	if err != nil {
		t.Fatalf("StreamOpts returned an error: %v", err)
	}
	for range ch {
	}
	<-drained

	f.mu.Lock()
	failures := f.failures
	killSwitched := f.killSwitch
	f.mu.Unlock()
	if failures != 1 || killSwitched {
		t.Fatalf("one stream attempt recorded failures=%d killSwitch=%v, want exactly one failure without kill-switch", failures, killSwitched)
	}
}

// ---------------------------------------------------------------------------
// CR-04 — the Runner's own pre-dispatch errors must BE dispatch failures.
// ---------------------------------------------------------------------------

// TestRunnerPreDispatchErrorsAreDispatchFailures pins the CR-04 fix.
//
// RunOpts and StreamOpts call recordDispatchFailure — writing OutcomeDispatchFailed
// into logs/tools.jsonl — and then returned a ToolError WITHOUT NeverStarted.
// ToolError.Is matches ErrDispatch only when NeverStarted is set, so the record
// said dispatch_failed while IsDispatchFailure(err) said false. Eleven files moved
// in 18-04/18-05 assert the opposite in prose and gate their graceful-skip arm on
// it; for an unregistered tool that arm was bypassed and the task fell through to
// the "exited non-zero" path, where res == nil then wipes its staging (CR-03).
//
// This predates phase 18 (verified against f436d2e) — the phase made it
// load-bearing rather than introducing it.
//
// Observed before the fix:
//
//	UNREGISTERED TOOL IS NOT CLASSIFIED AS A DISPATCH FAILURE: tool no-such-tool (exit -1): tool not registered
func TestRunnerPreDispatchErrorsAreDispatchFailures(t *testing.T) {
	r := NewRunner(&optsRecordingBackend{}, NewToolRegistry(), nil)

	t.Run("RunOpts/unregistered", func(t *testing.T) {
		_, err := r.RunOpts(context.Background(), "no-such-tool", nil, ExecOptions{})
		if err == nil {
			t.Fatal("an unregistered tool returned no error")
		}
		if !coreerrors.IsDispatchFailure(err) {
			t.Fatalf("UNREGISTERED TOOL IS NOT CLASSIFIED AS A DISPATCH FAILURE: %v — the "+
				"recorder wrote dispatch_failed for this same call, so the label "+
				"partition is inconsistent at its source (CR-04)", err)
		}
	})

	t.Run("StreamOpts/unregistered", func(t *testing.T) {
		_, err := r.StreamOpts(context.Background(), "no-such-tool", nil, ExecOptions{})
		if err == nil {
			t.Fatal("an unregistered tool returned no error")
		}
		if !coreerrors.IsDispatchFailure(err) {
			t.Fatalf("UNREGISTERED TOOL IS NOT CLASSIFIED AS A DISPATCH FAILURE (stream): %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// WR-08 — an empty-but-non-nil Stdin means EMPTY, not INHERIT.
// ---------------------------------------------------------------------------

// TestEmptyStdinSliceIsEmptyNotInherited pins the WR-08 fix.
//
// Both stdin guards used `len(opts.Stdin) > 0`, so `ExecOptions{Stdin: []byte{}}`
// left cmd.Stdin nil and the child inherited the PARENT's standard input. For any
// seam tool that reads stdin to EOF that means blocking on the operator's terminal
// until the tools.lock deadline fires. ExecOptions' own doc promises this only for
// a NIL Stdin.
//
// The tool here reads stdin to EOF and reports how many bytes it saw. Inheriting a
// terminal cannot be reproduced in `go test` (stdin is /dev/null, which EOFs), so
// the observable proof is the OTHER half of the same one-character bug: with
// StdinPath also set, `len() > 0` let StdinPath silently win instead of reporting
// the mutual-exclusion programming error.
func TestEmptyStdinSliceIsEmptyNotInherited(t *testing.T) {
	dir := t.TempDir()
	stdinFile := filepath.Join(dir, "in.txt")
	if err := os.WriteFile(stdinFile, []byte("FROM-THE-FILE\n"), 0o600); err != nil {
		t.Fatalf("write stdin file: %v", err)
	}
	script := filepath.Join(dir, "cat.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\ncat\n"), 0o700); err != nil { //nolint:gosec // test fixture must be executable
		t.Fatalf("write script: %v", err)
	}
	tool := &Tool{Name: "wr08", Path: script}
	be := &LocalBackend{}

	t.Run("empty slice plus StdinPath is the mutual-exclusion error", func(t *testing.T) {
		_, err := be.ExecOpts(context.Background(), tool, nil, ExecOptions{
			Stdin:     []byte{},
			StdinPath: stdinFile,
		})
		if err == nil {
			t.Fatal("an empty-but-non-nil Stdin alongside StdinPath was ACCEPTED — " +
				"StdinPath silently wins and the programming error goes unreported (WR-08)")
		}
		if !strings.Contains(err.Error(), "mutually exclusive") {
			t.Errorf("error does not report the mutual exclusion: %v", err)
		}
	})

	t.Run("empty slice alone yields empty stdin", func(t *testing.T) {
		res, err := be.ExecOpts(context.Background(), tool, nil, ExecOptions{Stdin: []byte{}})
		if err != nil {
			t.Fatalf("ExecOpts: %v", err)
		}
		if len(res.Stdout) != 0 {
			t.Errorf("an empty Stdin slice produced output %q — the child did not get an "+
				"empty standard input", res.Stdout)
		}
	})

	t.Run("nil Stdin with a StdinPath is still allowed", func(t *testing.T) {
		res, err := be.ExecOpts(context.Background(), tool, nil, ExecOptions{StdinPath: stdinFile})
		if err != nil {
			t.Fatalf("ExecOpts: %v", err)
		}
		if !strings.Contains(string(res.Stdout), "FROM-THE-FILE") {
			t.Errorf("StdinPath did not reach the child: %q", res.Stdout)
		}
	})
}

// ---------------------------------------------------------------------------
// WR-01 — the axiom refusal must see the TOOL, not only the options.
// ---------------------------------------------------------------------------

// TestAxiomRefusesToolCarriedWorkDirAndPrefix pins the WR-01 fix.
//
// After 18-02, Tool.WorkDir is the ONLY supported way to express a clone's working
// directory, and 18-05 routes nomore403/bypass4xx through it. Keying the refusal on
// ExecOptions alone meant such a tool went to the fleet with its cwd requirement
// silently dropped, and with an ArgvPrefix carrying absolute LOCAL clone paths.
func TestAxiomRefusesToolCarriedWorkDirAndPrefix(t *testing.T) {
	for _, tc := range []struct {
		name string
		tool *Tool
		want string
	}{
		{"WorkDir", &Tool{Name: "puredns", InputFlag: "-l", WorkDir: "/home/op/Tools/nomore403"}, "Tool.WorkDir"},
		{"ArgvPrefix", &Tool{Name: "puredns", InputFlag: "-l", ArgvPrefix: []string{"/home/op/Tools/x/venv/bin/python3", "main.py"}}, "Tool.ArgvPrefix"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &AxiomBackend{
				moduleMap: map[string]string{"puredns": "puredns-resolve"},
				local:     &optsRecordingBackend{},
			}
			_, err := a.ExecOpts(context.Background(), tc.tool,
				[]string{"-l", "/tmp/in.txt"}, ExecOptions{})
			if err == nil {
				t.Fatalf("a fleet-bound tool carrying %s was ACCEPTED — the requirement is "+
					"silently dropped on the fleet node (WR-01)", tc.want)
			}
			var axErr *coreerrors.AxiomFailure
			if !errors.As(err, &axErr) {
				t.Fatalf("error is %T, want *coreerrors.AxiomFailure", err)
			}
			if !strings.Contains(axErr.Error(), tc.want) {
				t.Errorf("refusal does not name %q: %v", tc.want, axErr)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// V-02 — routesToFleet must mirror BOTH of Exec's local-fallback arms.
// ---------------------------------------------------------------------------

// TestMappedToolWithNoInputFileIsServedLocally pins the V-02 fix.
//
// Exec falls back locally twice: unmapped/local-only/disabled, AND an unresolvable
// input file. routesToFleet mirrored only the first, so a MAPPED tool dispatched
// with options and no resolvable input file was still refused and still counted as
// a fleet failure — the CR-02 shape one arm deeper.
func TestMappedToolWithNoInputFileIsServedLocally(t *testing.T) {
	local := &optsRecordingBackend{}
	a := &AxiomBackend{
		moduleMap: map[string]string{"puredns": "puredns-resolve"},
		local:     local,
	}
	payload := []byte("served-locally")
	// Mapped tool, options carried, but NO resolvable input file.
	if _, err := a.ExecOpts(context.Background(),
		&Tool{Name: "puredns", InputFlag: "-l"}, nil,
		ExecOptions{Stdin: payload}); err != nil {
		t.Fatalf("a mapped tool with no input file was refused instead of served "+
			"locally — Exec would have delegated it (V-02): %v", err)
	}
	if !local.called {
		t.Fatal("the local leg was never reached")
	}
	if string(local.got.Stdin) != string(payload) {
		t.Errorf("local leg lost the stdin: got %q want %q", local.got.Stdin, payload)
	}
}

// ---------------------------------------------------------------------------
// WR-03 — Discover must not leave stale clone coordinates behind.
// ---------------------------------------------------------------------------

// TestDiscoverClearsStaleCloneCoordinates pins the WR-03 fix.
//
// The PATH branch cleared these and said so ("Clearing these keeps Discover
// idempotent"); the clone-FAILURE paths did not. A tool that resolved once and
// whose clone was then removed was reported in `missing` AND still carried a
// dispatchable Path and ArgvPrefix. Reachable in one process: healthcheck
// re-Discovers the same backend.Default that appctx.Boot already populated.
func TestDiscoverClearsStaleCloneCoordinates(t *testing.T) {
	root := t.TempDir()
	cloneDir := filepath.Join(root, "toolclone")
	if err := os.MkdirAll(filepath.Join(cloneDir, "venv", "bin"), 0o755); err != nil {
		t.Fatalf("mkdir clone: %v", err)
	}
	for _, f := range []string{filepath.Join(cloneDir, "main.py"), filepath.Join(cloneDir, "venv", "bin", "python3")} {
		if err := os.WriteFile(f, []byte("#!/bin/sh\n"), 0o700); err != nil { //nolint:gosec // test fixture must be executable
			t.Fatalf("write %s: %v", f, err)
		}
	}

	r := NewToolRegistry()
	r.SetToolsDir(root)
	tool := &Tool{
		Name:             "wr03-clone-tool",
		CloneDir:         "toolclone",
		CloneInterpreter: "venv/bin/python3",
		CloneEntry:       "main.py",
	}
	r.Register(tool)

	if err := r.Discover(context.Background()); err != nil {
		t.Fatalf("Discover: %v", err)
	}
	resolved, ok := r.Lookup(tool.Name)
	if !ok || resolved.Path == "" {
		t.Fatal("the clone did not resolve, so the staleness assertion below is worthless")
	}

	// The clone goes away between Discovers — a tool uninstalled mid-process.
	if err := os.RemoveAll(cloneDir); err != nil {
		t.Fatalf("remove clone: %v", err)
	}
	if err := r.Discover(context.Background()); err != nil {
		t.Fatalf("second Discover: %v", err)
	}

	tool, ok = r.Lookup(tool.Name)
	if !ok {
		t.Fatal("the registered tool disappeared after Discover")
	}
	if tool.Path != "" || tool.ArgvPrefix != nil || tool.WorkDir != "" {
		t.Errorf("STALE CLONE COORDINATES SURVIVED a failed re-Discover — the tool is "+
			"reported missing AND still dispatchable (WR-03): Path=%q ArgvPrefix=%v WorkDir=%q",
			tool.Path, tool.ArgvPrefix, tool.WorkDir)
	}
	if len(r.MissingRequired()) == 0 {
		t.Error("the tool is not reported missing after its clone was removed")
	}
}

// ---------------------------------------------------------------------------
// WR-02 — pre-Start returns must close the pipes they already created.
// ---------------------------------------------------------------------------

// TestStreamOptsDoesNotLeakPipesOnOptionError pins the WR-02 fix.
//
// os/exec closes parentIOPipes only inside Start's error path or Wait. StreamOpts
// creates stdout and stderr pipes BEFORE applyExecOptions, so returning on an
// option error leaked four descriptors per occurrence — reachable from ordinary
// input (a StdinPath naming an unopenable file, or a Stdin+StdinPath programming
// error), which makes it a slow leak in a long-lived MCP server, not a curiosity.
//
// The observation is the NUMBER the kernel gives the next descriptor. Unix
// allocates the lowest free fd, so if the loop leaks, the probe opened afterwards
// lands far higher than the one opened before. This is portable across darwin and
// linux and needs no /dev/fd — which os.ReadDir cannot list on darwin's fdesc
// filesystem, so a directory-count version of this test SKIPPED everywhere and
// proved nothing.
func TestStreamOptsDoesNotLeakPipesOnOptionError(t *testing.T) {
	dir := t.TempDir()
	probePath := filepath.Join(dir, "probe")
	if err := os.WriteFile(probePath, []byte("x"), 0o600); err != nil {
		t.Fatalf("write probe: %v", err)
	}
	nextFD := func() int {
		f, err := os.Open(probePath)
		if err != nil {
			t.Fatalf("open probe: %v", err)
		}
		fd := int(f.Fd())
		_ = f.Close()
		return fd
	}

	script := filepath.Join(dir, "noop.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil { //nolint:gosec // test fixture must be executable
		t.Fatalf("write script: %v", err)
	}
	tool := &Tool{Name: "wr02", Path: script}
	be := &LocalBackend{}

	// An option error guaranteed to fire AFTER the pipes are created: Stdin and
	// StdinPath both set is the mutual-exclusion programming error.
	bad := ExecOptions{Stdin: []byte("x"), StdinPath: filepath.Join(dir, "in.txt")}

	// Warm up so one-off allocations are not counted as a leak.
	if _, err := be.StreamOpts(context.Background(), tool, nil, bad); err == nil {
		t.Fatal("the option error did not fire, so this test observes nothing")
	}

	before := nextFD()
	const iterations = 40
	for i := 0; i < iterations; i++ {
		if _, err := be.StreamOpts(context.Background(), tool, nil, bad); err == nil {
			t.Fatalf("iteration %d: the option error did not fire", i)
		}
	}
	after := nextFD()

	// Each leaked occurrence costs four descriptors, so 40 iterations would push the
	// next fd up by well over a hundred. A small allowance absorbs runtime churn.
	if grew := after - before; grew > 8 {
		t.Errorf("PIPE DESCRIPTORS LEAKED across %d failed StreamOpts calls: next fd went "+
			"%d -> %d (+%d). os/exec closes parentIOPipes only in Start's error path or "+
			"Wait, so a pre-Start return must close them itself (WR-02)",
			iterations, before, after, grew)
	}
}

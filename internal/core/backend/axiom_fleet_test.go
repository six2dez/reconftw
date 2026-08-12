// axiom_fleet_test.go — regression guards for the SECOND round of --axiom bugs,
// found by forensics on the 4th live fleet (reconbox3, 2026-08-10). The fleet
// deployed and tore down cleanly, every tool "succeeded", and the scan still came
// back with passive-only results — because:
//
//	RC-D: `axiom-select <fleet>` matches NOTHING. Axiom names fleet members
//	      <fleet>01, <fleet>02, … so selected.conf was written EMPTY and every
//	      axiom-scan aborted with "Unable to reach any instance selected".
//	RC-E: axiom-scan aborts with a bare `exit` (status 0), so the backend treated
//	      the abort as success and surfaced axiom-scan's ASCII-art BANNER as tool
//	      output. That banner was written verbatim into artefacts/subdomains_dnsregs.json
//	      and inputs/resolved.{dnsx,tlsx,active}.txt — silent data poisoning, and
//	      no AxiomFailure meant FailoverBackend never fell back to local.
//	RC-F: the tool's own args were dropped, so even a healthy fleet ran the canned
//	      module (`cat input | dnsx -r … -o output`) instead of the `-recon -json`
//	      vector SubDNSTask parses.
//	RC-G: `axiom-rm <fleet>` matches nothing either — shutdown_on_end left PAID
//	      droplets running.
//
// Reuses axiomRecorder / axiomTestConfig from axiom_test.go.
package backend_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/six2dez/reconftw/internal/core/backend"
	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
)

// axiomScriptFake replays scripted axiom CLI behaviour: it records every
// invocation and returns canned stdout per tool name, without ever writing the
// -o output file (i.e. it models an axiom-scan that aborts while exiting 0).
type axiomScriptFake struct {
	stdoutFor map[string]string // tool name → stdout
	calls     []axiomCall
	// writeOut makes axiom-scan behave like a SUCCESSFUL dispatch: it writes results
	// to the -o path. Without it every dispatch fails the no-output-file check.
	writeOut []byte
}

type axiomCall struct {
	tool string
	args []string
}

func (f *axiomScriptFake) Exec(_ context.Context, t *backend.Tool, args []string) (*backend.Result, error) {
	name := ""
	if t != nil {
		name = t.Name
	}
	f.calls = append(f.calls, axiomCall{tool: name, args: args})
	if f.writeOut != nil && name == "axiom-scan" {
		for i, a := range args {
			if a == "-o" && i+1 < len(args) {
				_ = os.WriteFile(args[i+1], f.writeOut, 0o644)
			}
		}
	}
	return &backend.Result{Stdout: []byte(f.stdoutFor[name]), ExitCode: 0}, nil
}

func (f *axiomScriptFake) ExecEnv(ctx context.Context, t *backend.Tool, args []string, _ []string) (*backend.Result, error) {
	return f.Exec(ctx, t, args)
}

func (f *axiomScriptFake) Stream(_ context.Context, _ *backend.Tool, _ []string) (<-chan backend.Event, error) {
	ch := make(chan backend.Event)
	close(ch)
	return ch, nil
}

func (f *axiomScriptFake) StreamEnv(ctx context.Context, t *backend.Tool, args []string, _ []string) (<-chan backend.Event, error) {
	return f.Stream(ctx, t, args)
}

func (f *axiomScriptFake) HealthCheck(_ context.Context) error { return nil }
func (f *axiomScriptFake) Capacity() int                       { return 1 }

func (f *axiomScriptFake) lastCallFor(tool string) (axiomCall, bool) {
	for i := len(f.calls) - 1; i >= 0; i-- {
		if f.calls[i].tool == tool {
			return f.calls[i], true
		}
	}
	return axiomCall{}, false
}

// The real axiom-scan banner + abort line, ANSI escapes and all. This exact text
// is what ended up inside resolved.dnsx.txt on the live run.
const axiomUnreachableStdout = "\n" +
	"basically, axiom: the dynamic infrastructure framework for everybody!\n" +
	"\x1b[1;31mError: Unable to reach any instance selected. List all instances with " +
	"\x1b[0max ls\x1b[1;31m or select instances with \x1b[0max select\x1b[1;31m exiting..\x1b[0m\n"

// RC-D: Launch must select instances by PREFIX GLOB, not by the bare fleet name.
func TestAxiomLaunchSelectsWithGlob(t *testing.T) {
	fake := &axiomScriptFake{stdoutFor: map[string]string{
		"axiom-select": "Selected: [ test-fleet01 test-fleet02 ]\n",
	}}
	a := backend.NewAxiomBackendWithLocal(axiomTestConfig(2), backend.NewToolRegistry(), nil, fake)

	if err := a.Launch(context.Background()); err != nil {
		t.Fatalf("Launch: %v", err)
	}

	call, ok := fake.lastCallFor("axiom-select")
	if !ok {
		t.Fatal("axiom-select was never invoked")
	}
	if len(call.args) == 0 || call.args[0] != "test-fleet*" {
		t.Errorf("axiom-select called with %v, want [test-fleet*]\n"+
			"(RC-D: fleet members are named <fleet>01/02/… so the bare name selects nothing)", call.args)
	}
}

// RC-D: an empty "Selected: [ ]" is axiom-select's only signal that it matched
// nothing (it exits 0 regardless). Launch must report it and latch local mode.
func TestAxiomLaunchDetectsEmptySelection(t *testing.T) {
	fake := &axiomScriptFake{stdoutFor: map[string]string{
		"axiom-select": "\x1b[1;37mSelected: \x1b[0m[\x1b[0;32m  \x1b[0m]\n",
	}}
	a := backend.NewAxiomBackendWithLocal(axiomTestConfig(2), backend.NewToolRegistry(), nil, fake)

	err := a.Launch(context.Background())
	if err == nil {
		t.Fatal("Launch returned nil on an empty selection — the fleet is unusable and " +
			"every later axiom-scan will abort mid-scan")
	}
	var axErr *coreerrors.AxiomFailure
	if !errors.As(err, &axErr) {
		t.Fatalf("Launch error = %T (%v), want *AxiomFailure so FailoverBackend can fall back", err, err)
	}

	// …and the backend must now route tools locally rather than paying an SSH
	// preflight per tool for a fleet that cannot answer.
	tool := &backend.Tool{Name: "dnsx", Path: "/usr/bin/dnsx", InputFlag: "-l"}
	if _, execErr := a.Exec(context.Background(), tool, []string{"-l", "/tmp/in.txt"}); execErr != nil {
		t.Fatalf("Exec after failed Launch: %v", execErr)
	}
	call, ok := fake.lastCallFor("dnsx")
	if !ok {
		t.Errorf("after a failed Launch the tool was not run locally (calls: %+v)", fake.calls)
	} else if len(call.args) > 0 && call.args[0] == "/tmp/in.txt" {
		t.Errorf("tool was still dispatched through axiom-scan: %v", call.args)
	}
}

// RC-E: axiom-scan exits 0 on a dead fleet. With no output file the backend must
// return *AxiomFailure — NOT hand the caller axiom-scan's banner as tool output.
// Without the fix res.Stdout carries the banner and the caller writes it to disk.
func TestAxiomExecFailsWhenNoOutputFileWritten(t *testing.T) {
	dir := t.TempDir()
	inputFile := filepath.Join(dir, "passive.merged.txt")
	if err := os.WriteFile(inputFile, []byte("a.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fake := &axiomScriptFake{stdoutFor: map[string]string{
		"axiom-scan": axiomUnreachableStdout,
	}}
	a := backend.NewAxiomBackendWithLocal(axiomTestConfig(1), backend.NewToolRegistry(), nil, fake)
	tool := &backend.Tool{Name: "dnsx", Path: "/usr/bin/dnsx", InputFlag: "-l"}

	res, err := a.Exec(context.Background(), tool, []string{"-l", inputFile, "-json"})
	if err == nil {
		t.Fatalf("Exec returned nil error with res.Stdout = %q\n"+
			"(RC-E: axiom-scan exits 0 after aborting, so its BANNER was returned as tool "+
			"output and written verbatim into the scan artefacts)", safeStdout(res))
	}
	var axErr *coreerrors.AxiomFailure
	if !errors.As(err, &axErr) {
		t.Fatalf("Exec error = %T (%v), want *AxiomFailure so FailoverBackend re-runs it locally", err, err)
	}
	if !strings.Contains(err.Error(), "Unable to reach any instance") {
		t.Errorf("error %q does not carry axiom-scan's reason — the operator cannot tell why", err)
	}
	if res != nil {
		t.Errorf("Exec returned a non-nil Result alongside the failure: %q", safeStdout(res))
	}
}

// RC-E: the "fleet unreachable" abort must latch local mode, so one dead fleet
// does not cost an SSH preflight on every remaining tool of the scan.
func TestAxiomExecLatchesLocalAfterUnreachableFleet(t *testing.T) {
	dir := t.TempDir()
	inputFile := filepath.Join(dir, "in.txt")
	if err := os.WriteFile(inputFile, []byte("a.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fake := &axiomScriptFake{stdoutFor: map[string]string{"axiom-scan": axiomUnreachableStdout}}
	a := backend.NewAxiomBackendWithLocal(axiomTestConfig(1), backend.NewToolRegistry(), nil, fake)
	tool := &backend.Tool{Name: "dnsx", Path: "/usr/bin/dnsx", InputFlag: "-l"}

	_, _ = a.Exec(context.Background(), tool, []string{"-l", inputFile}) // trips the latch
	if _, err := a.Exec(context.Background(), tool, []string{"-l", inputFile}); err != nil {
		t.Fatalf("second Exec should have run locally, got %v", err)
	}
	if call, ok := fake.lastCallFor("dnsx"); !ok {
		t.Errorf("second Exec did not fall through to the local tool (calls: %+v)", fake.calls)
	} else if len(call.args) == 0 || call.args[0] != "-l" {
		t.Errorf("local passthrough mangled the args: %v", call.args)
	}
}

// RC-F: the tool's own flags must reach the module, or a healthy fleet still
// returns output in the wrong shape (the canned dnsx module has no -recon/-json).
// Local-only paths must NOT be forwarded — fleet nodes cannot read them.
func TestAxiomExecForwardsModuleArgs(t *testing.T) {
	dir := t.TempDir()
	inputFile := filepath.Join(dir, "passive.merged.txt")
	resolvers := filepath.Join(dir, "resolvers.txt")
	for _, p := range []string{inputFile, resolvers} {
		if err := os.WriteFile(p, []byte("x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	fake := &axiomScriptFake{stdoutFor: map[string]string{}}
	a := backend.NewAxiomBackendWithLocal(axiomTestConfig(1), backend.NewToolRegistry(), nil, fake)
	tool := &backend.Tool{Name: "dnsx", Path: "/usr/bin/dnsx", InputFlag: "-l"}

	// The real SubDNSTask vector.
	_, _ = a.Exec(context.Background(), tool, []string{
		"-l", inputFile, "-r", resolvers, "-recon", "-silent", "-retry", "3", "-json", "-t", "100",
	})

	call, ok := fake.lastCallFor("axiom-scan")
	if !ok {
		t.Fatalf("no axiom-scan dispatch (calls: %+v)", fake.calls)
	}
	joined := strings.Join(call.args, " ")

	for _, want := range []string{"-recon", "-silent", "-json", "-retry 3", "-t 100"} {
		if !strings.Contains(joined, want) {
			t.Errorf("axiom-scan args %q missing %q\n"+
				"(RC-F: without the tool's own flags the fleet runs the canned module and "+
				"returns output the task cannot parse)", joined, want)
		}
	}
	// The input file is supplied positionally by axiom-scan; -l must not repeat it.
	if strings.Contains(joined, "-l "+inputFile) {
		t.Errorf("input flag was forwarded as a module arg: %q", joined)
	}
	// A resolver list that exists HERE does not exist on a fleet node.
	if strings.Contains(joined, resolvers) {
		t.Errorf("local-only path %q was forwarded to the fleet: %q", resolvers, joined)
	}
	// Our own -m/-o must survive intact.
	if !strings.Contains(joined, "-m dnsx") || !strings.Contains(joined, "-o "+inputFile+".axiom.") {
		t.Errorf("axiom-scan control flags missing/mangled: %q", joined)
	}
}

// RC-F: puredns is positional — the `resolve` verb is already part of the module
// command, so forwarding it would corrupt the remote command line.
func TestAxiomExecDropsPurednsVerb(t *testing.T) {
	dir := t.TempDir()
	inputFile := filepath.Join(dir, "subs.txt")
	if err := os.WriteFile(inputFile, []byte("a.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fake := &axiomScriptFake{stdoutFor: map[string]string{}}
	a := backend.NewAxiomBackendWithLocal(axiomTestConfig(1), backend.NewToolRegistry(), nil, fake)
	tool := &backend.Tool{Name: "puredns", Path: "/usr/bin/puredns", InputFlag: ""}

	_, _ = a.Exec(context.Background(), tool, []string{"resolve", inputFile, "--quiet"})

	call, ok := fake.lastCallFor("axiom-scan")
	if !ok {
		t.Fatalf("no axiom-scan dispatch (calls: %+v)", fake.calls)
	}
	for _, arg := range call.args[1:] { // args[0] is the positional input
		if arg == "resolve" {
			t.Errorf("puredns verb forwarded to the module: %v", call.args)
		}
	}
	if !strings.Contains(strings.Join(call.args, " "), "--quiet") {
		t.Errorf("ordinary flags should still pass through: %v", call.args)
	}
}

// RC-G: shutdown_on_end must delete by prefix glob — `axiom-rm <fleet>` matches
// no instance, so the paid droplets kept running after every scan.
func TestAxiomShutdownRemovesFleetByGlob(t *testing.T) {
	cfg := axiomTestConfig(2)
	cfg.Axiom.ShutdownOnEnd = true
	fake := &axiomScriptFake{stdoutFor: map[string]string{}}
	a := backend.NewAxiomBackendWithLocal(cfg, backend.NewToolRegistry(), nil, fake)

	if err := a.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	call, ok := fake.lastCallFor("axiom-rm")
	if !ok {
		t.Fatal("axiom-rm was never invoked")
	}
	if len(call.args) == 0 || call.args[0] != "test-fleet*" {
		t.Errorf("axiom-rm called with %v, want [test-fleet* --force]\n"+
			"(RC-G: the bare fleet name matches no instance — droplets keep billing)", call.args)
	}
}

func safeStdout(res *backend.Result) string {
	if res == nil {
		return ""
	}
	return string(res.Stdout)
}

// axiomCtxFake records the context handed to every invocation so a test can assert
// that fleet-lifecycle calls are time-bounded.
type axiomCtxFake struct {
	deadlines map[string]bool // tool name → context had a deadline
	calls     []axiomCall
}

func newAxiomCtxFake() *axiomCtxFake {
	return &axiomCtxFake{deadlines: map[string]bool{}}
}

func (f *axiomCtxFake) Exec(ctx context.Context, t *backend.Tool, args []string) (*backend.Result, error) {
	name := ""
	if t != nil {
		name = t.Name
	}
	_, hasDeadline := ctx.Deadline()
	f.deadlines[name] = hasDeadline
	f.calls = append(f.calls, axiomCall{tool: name, args: args})
	return &backend.Result{Stdout: []byte("Selected: [ test-fleet01 ]\n"), ExitCode: 0}, nil
}

func (f *axiomCtxFake) ExecEnv(ctx context.Context, t *backend.Tool, args []string, _ []string) (*backend.Result, error) {
	return f.Exec(ctx, t, args)
}

func (f *axiomCtxFake) Stream(_ context.Context, _ *backend.Tool, _ []string) (<-chan backend.Event, error) {
	ch := make(chan backend.Event)
	close(ch)
	return ch, nil
}

func (f *axiomCtxFake) StreamEnv(ctx context.Context, t *backend.Tool, args []string, _ []string) (<-chan backend.Event, error) {
	return f.Stream(ctx, t, args)
}
func (f *axiomCtxFake) HealthCheck(_ context.Context) error { return nil }
func (f *axiomCtxFake) Capacity() int                       { return 1 }

// Every fleet-management call must carry its own deadline. Nothing else bounds them:
// LocalBackend takes its deadline from the context, and AxiomBackend bypasses Runner.
// A live run proved the cost — axiom-exec blocked inside Launch for the FULL 120-minute
// scan budget, so the scan produced nothing and died on context cancellation.
func TestAxiomLifecycleCallsAreTimeBounded(t *testing.T) {
	dir := t.TempDir()
	resolvers := filepath.Join(dir, "resolvers.txt")
	if err := os.WriteFile(resolvers, []byte("1.1.1.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := axiomTestConfig(2)
	cfg.Axiom.FleetLaunch = true
	cfg.Axiom.ShutdownOnEnd = true
	cfg.Paths.Resolvers = resolvers
	cfg.Advanced.Tools.Axiom.ResolversPath = "/home/op/lists/resolvers.txt"

	fake := newAxiomCtxFake()
	a := backend.NewAxiomBackendWithLocal(cfg, backend.NewToolRegistry(), nil, fake)

	// context.Background() has no deadline — any deadline observed downstream can
	// only have been added by the lifecycle code itself.
	if err := a.Launch(context.Background()); err != nil {
		t.Fatalf("Launch: %v", err)
	}
	if err := a.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	for _, tool := range []string{"axiom-fleet2", "axiom-select", "axiom-scp", "axiom-rm"} {
		bounded, called := fake.deadlines[tool]
		if !called {
			t.Errorf("%s was never invoked (calls: %+v)", tool, fake.calls)
			continue
		}
		if !bounded {
			t.Errorf("%s ran on an unbounded context — it can hang the entire scan", tool)
		}
	}
}

// Resolver propagation must use axiom-scp (local file → fleet path). The old
// axiom-exec heredoc expanded `$(cat …)` on the REMOTE node and wrote to
// /tmp/resolvers.txt, which no axiom module reads — and it hung.
func TestAxiomResolverPropagationUsesScp(t *testing.T) {
	dir := t.TempDir()
	resolvers := filepath.Join(dir, "resolvers.txt")
	trusted := filepath.Join(dir, "trusted.txt")
	for _, p := range []string{resolvers, trusted} {
		if err := os.WriteFile(p, []byte("1.1.1.1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cfg := axiomTestConfig(2)
	cfg.Paths.Resolvers = resolvers
	cfg.Paths.ResolversTrusted = trusted
	cfg.Advanced.Tools.Axiom.ResolversPath = "/home/op/lists/resolvers.txt"
	cfg.Advanced.Tools.Axiom.ResolversTrustedPath = "/home/op/lists/resolvers_trusted.txt"

	fake := &axiomScriptFake{stdoutFor: map[string]string{
		"axiom-select": "Selected: [ test-fleet01 ]\n",
	}}
	a := backend.NewAxiomBackendWithLocal(cfg, backend.NewToolRegistry(), nil, fake)
	if err := a.Launch(context.Background()); err != nil {
		t.Fatalf("Launch: %v", err)
	}

	if _, used := fake.lastCallFor("axiom-exec"); used {
		t.Error("axiom-exec is still used for propagation — that heredoc hung a live scan for 2h")
	}
	call, ok := fake.lastCallFor("axiom-scp")
	if !ok {
		t.Fatalf("axiom-scp was never invoked (calls: %+v)", fake.calls)
	}
	want := "test-fleet*:/home/op/lists/resolvers_trusted.txt"
	if len(call.args) != 2 || call.args[0] != trusted || call.args[1] != want {
		t.Errorf("axiom-scp args = %v, want [%s %s]", call.args, trusted, want)
	}
}

// A local list that does not exist must be skipped, not uploaded blindly.
func TestAxiomResolverPropagationSkipsMissingLocalFile(t *testing.T) {
	cfg := axiomTestConfig(2)
	cfg.Paths.Resolvers = "/nonexistent/resolvers.txt"
	cfg.Advanced.Tools.Axiom.ResolversPath = "/home/op/lists/resolvers.txt"

	fake := &axiomScriptFake{stdoutFor: map[string]string{
		"axiom-select": "Selected: [ test-fleet01 ]\n",
	}}
	a := backend.NewAxiomBackendWithLocal(cfg, backend.NewToolRegistry(), nil, fake)
	if err := a.Launch(context.Background()); err != nil {
		t.Fatalf("Launch: %v", err)
	}
	if _, ok := fake.lastCallFor("axiom-scp"); ok {
		t.Error("axiom-scp ran for a local file that does not exist")
	}
}

// Concurrent dispatches must not share an output file. Several tasks read the same
// input (inputs/passive.merged.txt): a live run fired puredns-resolve plus three dnsx
// variants within 30ms, all writing inputs/passive.merged.txt.axiom.out — so one
// dispatch's pre-run cleanup could delete another's finished results, and a read could
// return the wrong tool's output.
func TestAxiomDispatchOutputFilesAreUnique(t *testing.T) {
	dir := t.TempDir()
	inputFile := filepath.Join(dir, "passive.merged.txt")
	if err := os.WriteFile(inputFile, []byte("a.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// writeOut = these dispatches SUCCEED. Without it the consecutive-failure latch
	// would (correctly) route the 3rd and 4th to local, leaving nothing to compare.
	fake := &axiomScriptFake{stdoutFor: map[string]string{}, writeOut: []byte("x.example.com\n")}
	a := backend.NewAxiomBackendWithLocal(axiomTestConfig(1), backend.NewToolRegistry(), nil, fake)

	// The real overlap: three dnsx variants + puredns resolve on one input file.
	for _, tc := range []struct {
		tool *backend.Tool
		args []string
	}{
		{&backend.Tool{Name: "dnsx", Path: "dnsx", InputFlag: "-l"}, []string{"-l", inputFile, "-recon", "-json"}},
		{&backend.Tool{Name: "dnsx", Path: "dnsx", InputFlag: "-l"}, []string{"-l", inputFile, "-rcode", "noerror"}},
		{&backend.Tool{Name: "dnsx", Path: "dnsx", InputFlag: "-l"}, []string{"-l", inputFile, "-srv"}},
		{&backend.Tool{Name: "puredns", Path: "puredns", InputFlag: ""}, []string{"resolve", inputFile, "--quiet"}},
	} {
		_, _ = a.Exec(context.Background(), tc.tool, tc.args)
	}

	seen := map[string]bool{}
	for _, c := range fake.calls {
		if c.tool != "axiom-scan" {
			continue
		}
		for i, arg := range c.args {
			if arg == "-o" && i+1 < len(c.args) {
				if seen[c.args[i+1]] {
					t.Errorf("output file %q reused across dispatches — concurrent tasks would "+
						"delete or read each other's results", c.args[i+1])
				}
				seen[c.args[i+1]] = true
			}
		}
	}
	if len(seen) != 4 {
		t.Errorf("got %d distinct output files, want 4 (calls: %+v)", len(seen), fake.calls)
	}
}

// blockingFake holds every axiom-scan dispatch until released, so a test can observe
// how many run concurrently and how far apart they start.
type blockingFake struct {
	mu      sync.Mutex
	starts  []time.Time
	inFlusk int
	maxCon  int
	release chan struct{}
}

func (f *blockingFake) Exec(_ context.Context, t *backend.Tool, args []string) (*backend.Result, error) {
	if t != nil && t.Name == "axiom-scan" {
		f.mu.Lock()
		f.starts = append(f.starts, time.Now())
		f.inFlusk++
		if f.inFlusk > f.maxCon {
			f.maxCon = f.inFlusk
		}
		f.mu.Unlock()
		<-f.release
		f.mu.Lock()
		f.inFlusk--
		f.mu.Unlock()
	}
	return &backend.Result{ExitCode: 0}, nil
}

func (f *blockingFake) ExecEnv(ctx context.Context, t *backend.Tool, args []string, _ []string) (*backend.Result, error) {
	return f.Exec(ctx, t, args)
}

func (f *blockingFake) Stream(_ context.Context, _ *backend.Tool, _ []string) (<-chan backend.Event, error) {
	ch := make(chan backend.Event)
	close(ch)
	return ch, nil
}

func (f *blockingFake) StreamEnv(ctx context.Context, t *backend.Tool, args []string, _ []string) (<-chan backend.Event, error) {
	return f.Stream(ctx, t, args)
}
func (f *blockingFake) HealthCheck(_ context.Context) error { return nil }
func (f *blockingFake) Capacity() int                       { return 1 }

// Fleet dispatches must be serialized and spaced apart. axiom-scan identifies a scan
// by `$module+$(date +…-%1N)` — module name plus a ONE-DECISECOND timestamp — so two
// dispatches of the same module in the same 0.1s share a uid, and therefore share the
// remote scan directory and tmux session name on every node. A live run fired three
// dnsx dispatches 30ms apart: they collapsed into a single axiom log dir, one returned
// in 5s and the other two hung until their timeouts (89m).
func TestAxiomDispatchesAreSerializedAndSpaced(t *testing.T) {
	dir := t.TempDir()
	inputFile := filepath.Join(dir, "passive.merged.txt")
	if err := os.WriteFile(inputFile, []byte("a.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fake := &blockingFake{release: make(chan struct{})}
	a := backend.NewAxiomBackendWithLocal(axiomTestConfig(1), backend.NewToolRegistry(), nil, fake)
	tool := &backend.Tool{Name: "dnsx", Path: "dnsx", InputFlag: "-l"}

	// Three concurrent dnsx dispatches on one input — the exact live shape.
	var wg sync.WaitGroup
	for i := range 3 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _ = a.Exec(context.Background(), tool, []string{"-l", inputFile, "-flag", string(rune('a' + i))})
		}(i)
	}

	// Let them queue, then drain one at a time.
	time.Sleep(300 * time.Millisecond)
	go func() {
		for range 3 {
			fake.release <- struct{}{}
			time.Sleep(50 * time.Millisecond)
		}
	}()
	wg.Wait()

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.maxCon > 1 {
		t.Errorf("%d dispatches ran concurrently, want 1 — concurrent axiom-scans of the same "+
			"module collide on axiom's uid and hang", fake.maxCon)
	}
	if len(fake.starts) != 3 {
		t.Fatalf("got %d dispatches, want 3", len(fake.starts))
	}
	for i := 1; i < len(fake.starts); i++ {
		if gap := fake.starts[i].Sub(fake.starts[i-1]); gap < 200*time.Millisecond {
			t.Errorf("dispatch %d started %v after the previous one — under axiom's 0.1s uid "+
				"granularity they can still share a scan id", i, gap)
		}
	}
}

// A fleet that cannot return two dispatches will not return the next twenty, and each
// attempt costs axiomDispatchTimeout (10m). After the latch trips, every remaining tool
// must go straight to local — this is what keeps a broken fleet from consuming the whole
// scan budget, as it did live (89m per dispatch, all tools blocked behind the first).
func TestAxiomAbandonsFleetAfterRepeatedDispatchFailures(t *testing.T) {
	dir := t.TempDir()
	inputFile := filepath.Join(dir, "in.txt")
	if err := os.WriteFile(inputFile, []byte("a.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// No writeOut → axiom-scan "succeeds" but never produces the results file.
	fake := &axiomScriptFake{stdoutFor: map[string]string{}}
	a := backend.NewAxiomBackendWithLocal(axiomTestConfig(1), backend.NewToolRegistry(), nil, fake)
	tool := &backend.Tool{Name: "dnsx", Path: "dnsx", InputFlag: "-l"}

	for i := range 4 {
		_, _ = a.Exec(context.Background(), tool, []string{"-l", inputFile, "-n", string(rune('a' + i))})
	}

	dispatches := 0
	for _, c := range fake.calls {
		if c.tool == "axiom-scan" {
			dispatches++
		}
	}
	if dispatches > 2 {
		t.Errorf("%d dispatches attempted, want at most 2 — a dead fleet must be abandoned, "+
			"not retried for every tool in the scan", dispatches)
	}
	last := fake.calls[len(fake.calls)-1]
	if last.tool != "dnsx" {
		t.Errorf("after the latch the tool should run locally; last call was %q with %v", last.tool, last.args)
	}
}

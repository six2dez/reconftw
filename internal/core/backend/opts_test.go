// opts_test.go — the ExecOptions seam (plan 18-01), proven end to end.
//
// These tests are INTERNAL (package backend) for two reasons: applyToolContract is
// unexported, and an external test file importing internal/core/testutil would be
// an import cycle (testutil imports backend). The failover leg therefore uses a
// local recording fake rather than testutil.MockBackend — same assertion, no cycle.
package backend

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	stderrors "errors"

	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
)

// asAxiom is errors.As, named so the assertion above reads as the question it asks.
func asAxiom(err error, target **coreerrors.AxiomFailure) bool {
	return stderrors.As(err, target)
}

// findBin resolves a real system binary WITHOUT importing os/exec, so this test
// file adds no raw-subprocess surface of its own. Skips with a reason when the
// binary is unresolvable, per the plan's instruction.
func findBin(t *testing.T, name string) string {
	t.Helper()
	for _, dir := range []string{"/bin", "/usr/bin"} {
		p := filepath.Join(dir, name)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	t.Skipf("skipping: %q not resolvable under /bin or /usr/bin on this host", name)
	return ""
}

func newOptsRunner(t *testing.T, tool *Tool) (*Runner, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "logs", "tools.jsonl")
	reg := NewToolRegistry()
	reg.Register(tool)
	r := NewRunner(&LocalBackend{}, reg, nil)
	r.Recorder = NewToolRecorder(path, nil)
	return r, path
}

// TestRunOptsDeliversStdinToARealProcess is the tracer's BINDING proof: bytes
// handed to Runner.RunOpts crossed every layer into a real process's standard
// input. The assertion is on the PROCESS'S OWN OUTPUT — `cat` can only echo what
// it actually read — and not on a mock's recorded call, which would prove the
// test rather than the seam.
func TestRunOptsDeliversStdinToARealProcess(t *testing.T) {
	catPath := findBin(t, "cat")
	r, _ := newOptsRunner(t, &Tool{Name: "catstdin", Path: catPath})

	payload := []byte("8.8.8.8\n1.1.1.1\n")
	res, err := r.RunOpts(context.Background(), "catstdin", nil, ExecOptions{Stdin: payload})
	if err != nil {
		t.Fatalf("RunOpts returned error: %v", err)
	}
	if got := string(res.Stdout); got != string(payload) {
		t.Errorf("the process did not receive the stdin bytes:\n got = %q\nwant = %q", got, payload)
	}
}

// TestRunOptsStdinIsNotRecorded pins T-18-01-01. Stdin content routinely carries
// secrets (vulns/xss.go pipes a URL corpus whose query strings carry tokens), and
// logs/tools.jsonl is a file operators paste into issues.
//
// PRESENCE IS ASSERTED BEFORE ABSENCE, deliberately: an absence assertion against
// a file that was never written is worth nothing.
func TestRunOptsStdinIsNotRecorded(t *testing.T) {
	catPath := findBin(t, "cat")
	r, recPath := newOptsRunner(t, &Tool{Name: "catstdin", Path: catPath})

	const canary = "CANARY-b3f1e9d7-DO-NOT-RECORD"
	if _, err := r.RunOpts(context.Background(), "catstdin", []string{}, ExecOptions{
		Stdin: []byte(canary + "\n"),
	}); err != nil {
		t.Fatalf("RunOpts returned error: %v", err)
	}

	raw, err := os.ReadFile(recPath) //nolint:gosec // test-owned temp path
	if err != nil {
		t.Fatalf("reading the recorder file: %v", err)
	}

	// (a) PRESENCE FIRST — the recorder actually wrote a start record for this tool.
	var sawStart bool
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var rec InvocationRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("record is not valid JSON: %v (line %q)", err, line)
		}
		if rec.Tool == "catstdin" && rec.Outcome == "" {
			sawStart = true
		}
	}
	if !sawStart {
		t.Fatalf("no start record for catstdin was written — the absence assertion below "+
			"would be vacuous. File contents:\n%s", raw)
	}

	// (b) ONLY THEN ABSENCE — the canary reached the process but not the record.
	if strings.Contains(string(raw), canary) {
		t.Errorf("STDIN CONTENT LEAKED INTO THE INVOCATION RECORD (T-18-01-01).\n"+
			"canary %q found in %s:\n%s", canary, recPath, raw)
	}
}

// optsRecordingBackend records the ExecOptions it received. It is the failover's
// LOCAL leg in the test below.
type optsRecordingBackend struct {
	got    ExecOptions
	called bool
}

func (b *optsRecordingBackend) Exec(ctx context.Context, t *Tool, args []string) (*Result, error) {
	return b.ExecOpts(ctx, t, args, ExecOptions{})
}

func (b *optsRecordingBackend) ExecEnv(ctx context.Context, t *Tool, args []string, env []string) (*Result, error) {
	return b.ExecOpts(ctx, t, args, ExecOptions{Env: env})
}

func (b *optsRecordingBackend) ExecOpts(_ context.Context, _ *Tool, _ []string, opts ExecOptions) (*Result, error) {
	b.got, b.called = opts, true
	return &Result{ExitCode: 0}, nil
}

func (b *optsRecordingBackend) Stream(ctx context.Context, t *Tool, args []string) (<-chan Event, error) {
	return b.StreamOpts(ctx, t, args, ExecOptions{})
}

func (b *optsRecordingBackend) StreamEnv(ctx context.Context, t *Tool, args []string, env []string) (<-chan Event, error) {
	return b.StreamOpts(ctx, t, args, ExecOptions{Env: env})
}

func (b *optsRecordingBackend) StreamOpts(_ context.Context, _ *Tool, _ []string, opts ExecOptions) (<-chan Event, error) {
	b.got, b.called = opts, true
	ch := make(chan Event)
	close(ch)
	return ch, nil
}

func (b *optsRecordingBackend) HealthCheck(context.Context) error { return nil }
func (b *optsRecordingBackend) Capacity() int                     { return 1 }

// axiomRefusingPrimary stands in for AxiomBackend's refusal: it fails every
// dispatch with the *AxiomFailure that FailoverBackend keys on.
type axiomRefusingPrimary struct{ optsRecordingBackend }

func (p *axiomRefusingPrimary) ExecOpts(_ context.Context, t *Tool, _ []string, _ ExecOptions) (*Result, error) {
	return nil, &coreerrors.AxiomFailure{Operation: "exec_opts", Inner: errStub{t.Name}}
}

type errStub struct{ n string }

func (e errStub) Error() string { return "axiom cannot serve " + e.n }

// TestFailoverForwardsStdinToTheLocalLeg pins T-18-01-04, the whole reason
// ExecOptions.Stdin is []byte rather than an io.Reader. A fallback that dropped
// the stdin would hand the tool an EMPTY standard input and return a clean
// zero-finding success — indistinguishable from a genuinely empty result.
func TestFailoverForwardsStdinToTheLocalLeg(t *testing.T) {
	local := &optsRecordingBackend{}
	f := &FailoverBackend{Primary: &axiomRefusingPrimary{}, Fallback: local}

	payload := []byte("stdin-must-survive-the-retry")
	if _, err := f.ExecOpts(context.Background(), &Tool{Name: "x"}, nil, ExecOptions{
		Stdin: payload,
	}); err != nil {
		t.Fatalf("ExecOpts returned error: %v", err)
	}

	if !local.called {
		t.Fatal("the local fallback leg was never reached")
	}
	if string(local.got.Stdin) != string(payload) {
		t.Errorf("the retry leg did not receive the stdin bytes:\n got = %q\nwant = %q",
			local.got.Stdin, payload)
	}
}

// TestAxiomRefusesStdin asserts the refusal is a TYPED *AxiomFailure — not a nil
// error (which would mean the stdin was silently dropped and the tool ran on the
// fleet with empty input) and not a generic error (which FailoverBackend would
// not key on, so the local leg would never engage). T-18-01-05.
//
// SCOPE, and why this is not the production-shaped case (V-03). It uses a
// ZERO-VALUED &AxiomBackend{}, whose nil local leg makes routesToFleet report
// true — the only reason a refusal is reachable at all here. In production
// hakip2host is UNMAPPED and local != nil, so after the CR-02 reordering that
// exact dispatch no longer refuses: it is served locally with its stdin intact,
// which is the fix, not a regression.
//
// What this test still pins is the refusal's SHAPE: typed, and naming the field.
// The production-shaped contract — a genuinely fleet-bound tool refusing — lives
// in TestMappedToolWithOptionsStillRefuses and TestAxiomRefusesToolCarriedWorkDirAndPrefix
// (review_fixes_test.go), and TestMappedToolWithNoInputFileIsServedLocally pins
// the other side. Read as a production contract on its own, this comment would be
// asserting an invariant that is no longer true — the class this phase exists to
// delete, so it is stated rather than left implied.
func TestAxiomRefusesStdin(t *testing.T) {
	a := &AxiomBackend{}
	tool := &Tool{Name: "hakip2host"}

	for _, tc := range []struct {
		name string
		opts ExecOptions
		want string
	}{
		{"stdin", ExecOptions{Stdin: []byte("x")}, "Stdin"},
		{"stdinpath", ExecOptions{StdinPath: "/tmp/x"}, "StdinPath"},
		{"dir", ExecOptions{Dir: "/tmp"}, "Dir"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := a.ExecOpts(context.Background(), tool, nil, tc.opts)
			if err == nil {
				t.Fatal("axiom accepted an option it cannot serve — the stdin would " +
					"have been silently dropped and the tool run with empty input")
			}
			var axErr *coreerrors.AxiomFailure
			if !asAxiom(err, &axErr) {
				t.Fatalf("error is %T, want *coreerrors.AxiomFailure — FailoverBackend "+
					"keys on that type, so a generic error means the local leg never engages", err)
			}
			if !strings.Contains(axErr.Error(), tc.want) {
				t.Errorf("refusal does not name the unsupported option %q: %v", tc.want, axErr)
			}
		})
	}
}

// -------------------------------------------------------------------------
// Task 3: ArgvPrefix and WorkDir
// -------------------------------------------------------------------------

// TestApplyToolContractPrefixOrdering pins the ORDER. ArgvPrefix comes first
// because it is part of the executable's IDENTITY (an interpreter plus a script);
// DefaultArgs are flags TO the program the prefix names, so they must follow it.
// Getting this backwards would hand python3 a flag where it expects a script.
func TestApplyToolContractPrefixOrdering(t *testing.T) {
	tool := &Tool{
		Name:        "regulator",
		ArgvPrefix:  []string{"/x/main.py"},
		DefaultArgs: []string{"-q"},
	}
	_, cancel, got := applyToolContract(context.Background(), tool, []string{"-d", "example.com"})
	defer cancel()

	want := []string{"/x/main.py", "-q", "-d", "example.com"}
	if !equalArgs(got, want) {
		t.Errorf("argv = %v, want %v", got, want)
	}
}

// TestApplyToolContractEmptyPrefixIsIdentity is the no-op guarantee: a Tool with
// no ArgvPrefix must produce EXACTLY today's argv, so no existing caller changes.
// The assertion is on the FULL slice, not on it being non-empty.
func TestApplyToolContractEmptyPrefixIsIdentity(t *testing.T) {
	tool := &Tool{Name: "subfinder", DefaultArgs: []string{"-silent"}}
	_, cancel, got := applyToolContract(context.Background(), tool, []string{"-d", "example.com"})
	defer cancel()

	want := []string{"-silent", "-d", "example.com"}
	if !equalArgs(got, want) {
		t.Errorf("argv = %v, want %v — the zero-prefix path must be byte-for-byte today's", got, want)
	}

	// And with no DefaultArgs either, the caller's args pass through untouched.
	_, cancel2, bare := applyToolContract(context.Background(), &Tool{Name: "x"}, []string{"-a", "-b"})
	defer cancel2()
	if !equalArgs(bare, []string{"-a", "-b"}) {
		t.Errorf("argv = %v, want [-a -b]", bare)
	}
}

func equalArgs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestWorkDirReachesTheProcess asserts on a REAL PROCESS'S OBSERVABLE BEHAVIOUR —
// /bin/pwd reports the directory it was actually started in — and not on the
// exec.Cmd struct field, which would only prove we assigned it.
func TestWorkDirReachesTheProcess(t *testing.T) {
	pwdPath := findBin(t, "pwd")

	toolDir := t.TempDir()
	optsDir := t.TempDir()

	t.Run("tool_workdir_reaches_the_process", func(t *testing.T) {
		r, _ := newOptsRunner(t, &Tool{Name: "pwdtool", Path: pwdPath, WorkDir: toolDir})
		res, err := r.RunOpts(context.Background(), "pwdtool", nil, ExecOptions{})
		if err != nil {
			t.Fatalf("RunOpts: %v", err)
		}
		assertSameDir(t, strings.TrimSpace(string(res.Stdout)), toolDir)
	})

	t.Run("opts_dir_wins_over_tool_workdir", func(t *testing.T) {
		r, _ := newOptsRunner(t, &Tool{Name: "pwdtool", Path: pwdPath, WorkDir: toolDir})
		res, err := r.RunOpts(context.Background(), "pwdtool", nil, ExecOptions{Dir: optsDir})
		if err != nil {
			t.Fatalf("RunOpts: %v", err)
		}
		assertSameDir(t, strings.TrimSpace(string(res.Stdout)), optsDir)
	})

	t.Run("neither_set_inherits_the_parent", func(t *testing.T) {
		r, _ := newOptsRunner(t, &Tool{Name: "pwdtool", Path: pwdPath})
		res, err := r.RunOpts(context.Background(), "pwdtool", nil, ExecOptions{})
		if err != nil {
			t.Fatalf("RunOpts: %v", err)
		}
		parent, err := os.Getwd()
		if err != nil {
			t.Fatalf("Getwd: %v", err)
		}
		assertSameDir(t, strings.TrimSpace(string(res.Stdout)), parent)
	})
}

// assertSameDir compares two paths after resolving symlinks — macOS reports
// /private/var for a /var TempDir, so a raw string compare would fail for a
// reason that has nothing to do with the seam.
func assertSameDir(t *testing.T, got, want string) {
	t.Helper()
	g, err := filepath.EvalSymlinks(got)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q): %v", got, err)
	}
	w, err := filepath.EvalSymlinks(want)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q): %v", want, err)
	}
	if g != w {
		t.Errorf("the process ran in %q, want %q", g, w)
	}
}

// TestStdinMutuallyExclusive: setting both Stdin and StdinPath is a programming
// error the implementation REPORTS rather than resolves — and it must dispatch
// NOTHING, so the failure is labelled dispatch_failed rather than looking like a
// tool that ran and failed. That is the label partition documented at
// Runner.execRecorded, and it has to keep holding.
func TestStdinMutuallyExclusive(t *testing.T) {
	catPath := findBin(t, "cat")
	r, recPath := newOptsRunner(t, &Tool{Name: "catstdin", Path: catPath})

	_, err := r.RunOpts(context.Background(), "catstdin", nil, ExecOptions{
		Stdin:     []byte("a"),
		StdinPath: "/tmp/does-not-matter",
	})
	if err == nil {
		t.Fatal("both Stdin and StdinPath were accepted — one of them was silently ignored")
	}
	if !coreerrors.IsDispatchFailure(err) {
		t.Errorf("error %v is not a dispatch failure; a tool that never ran must not "+
			"be labelled as one that ran and failed", err)
	}

	raw, err := os.ReadFile(recPath) //nolint:gosec // test-owned temp path
	if err != nil {
		t.Fatalf("reading the recorder file: %v", err)
	}
	if !strings.Contains(string(raw), `"dispatch_failed"`) {
		t.Errorf("the invocation was not recorded as dispatch_failed:\n%s", raw)
	}
}

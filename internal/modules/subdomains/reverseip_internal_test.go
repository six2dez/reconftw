// reverseip_internal_test.go — INTERNAL tests (package subdomains) for the
// hakip2host reverse-IP fold (13-01 Task 1). Internal because they override the
// unexported hakip2hostRunner package var to inject canned tool output without a
// real binary, and exercise the unexported parse/scope helpers.
package subdomains

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/core/task"
)

// -------------------------------------------------------------------------
// Internal test doubles (shared with resolve degrade tests)
// -------------------------------------------------------------------------

// stubBackend returns a canned error (Exec/Stream) or canned stdout/stream lines.
type stubBackend struct {
	err      error
	stdout   []byte
	streamLn []string
}

func (b *stubBackend) Exec(_ context.Context, _ *backend.Tool, _ []string) (*backend.Result, error) {
	if b.err != nil {
		return nil, b.err
	}
	return &backend.Result{Stdout: b.stdout, ExitCode: 0}, nil
}

func (b *stubBackend) ExecEnv(ctx context.Context, t *backend.Tool, args []string, _ []string) (*backend.Result, error) {
	return b.Exec(ctx, t, args)
}

func (b *stubBackend) Stream(_ context.Context, _ *backend.Tool, _ []string) (<-chan backend.Event, error) {
	if b.err != nil {
		return nil, b.err
	}
	ch := make(chan backend.Event, len(b.streamLn))
	for _, l := range b.streamLn {
		ch <- backend.Event{Line: []byte(l)}
	}
	close(ch)
	return ch, nil
}

func (b *stubBackend) StreamEnv(ctx context.Context, t *backend.Tool, args []string, _ []string) (<-chan backend.Event, error) {
	return b.Stream(ctx, t, args)
}

func (b *stubBackend) HealthCheck(_ context.Context) error { return nil }
func (b *stubBackend) Capacity() int                       { return 1 }

// scopeTree is an output.Interface double applying a real DefaultScopeFilter so
// in-scope filtering (T-13-01-01) can be exercised.
type scopeTree struct{ patterns []string }

func (s *scopeTree) Append(_ string, _ [][]byte) error { return nil }
func (s *scopeTree) InScope(host string) bool {
	f := &output.DefaultScopeFilter{Patterns: s.patterns}
	return f.IsInScope(host)
}

// internalTestApp builds a minimal AppContext for internal resolve tests.
func internalTestApp(workDir string, be backend.Backend, tree output.Interface) *appctx.AppContext {
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "dnsx"})
	reg.Register(&backend.Tool{Name: "testtool"})
	return &appctx.AppContext{
		Tools:  backend.NewRunner(be, reg, nil),
		Tree:   tree,
		Target: &appctx.Target{Domain: "example.com", WorkDir: workDir},
		Cfg:    &config.Config{},
	}
}

// -------------------------------------------------------------------------
// parseHakip2hostHosts: field-3 extraction + in-scope filter + dedup
// -------------------------------------------------------------------------

func TestParseHakip2hostHostsFiltersScope(t *testing.T) {
	app := &appctx.AppContext{Tree: &scopeTree{patterns: []string{"*.example.com"}}}
	// bash awk '{print $3}': the 3rd whitespace field is the hostname.
	out := "[PTR] 1.2.3.4 sub.example.com\n" +
		"[SSLCERT] 1.2.3.4 evil.com\n" + // off-scope — must be dropped (T-13-01-01)
		"[PTR] 1.2.3.4 sub.example.com\n" // duplicate — must dedup
	got := parseHakip2hostHosts(out, app)
	if len(got) != 1 || got[0] != "sub.example.com" {
		t.Errorf("parseHakip2hostHosts = %v, want [sub.example.com] (evil.com off-scope, dedup)", got)
	}
}

// -------------------------------------------------------------------------
// SubDNSTask hakip2host gate: Enabled → invoked + staged; disabled → skipped
// -------------------------------------------------------------------------

func TestSubDNSReverseIPGate(t *testing.T) {
	// dnsx record with a PUBLIC A record so the reverse-IP feed is non-empty.
	dnsregs := []byte(`{"host":"api.example.com","a":["8.8.8.8"]}` + "\n")

	orig := hakip2hostRunner
	t.Cleanup(func() { hakip2hostRunner = orig })

	newStub := func(calls *int) {
		hakip2hostRunner = func(_ context.Context, _ *appctx.AppContext, _ []string) (string, error) {
			*calls++
			return "8.8.8.8 PTR host.example.com\n", nil
		}
	}

	t.Run("enabled_invokes_and_stages", func(t *testing.T) {
		var calls int
		newStub(&calls)
		workDir := t.TempDir()
		app := internalTestApp(workDir, &stubBackend{stdout: dnsregs}, &scopeTree{patterns: []string{"*.example.com"}})
		app.Cfg.Subdomains.ReverseIP.Enabled = true

		res, err := SubDNSTask{}.Run(context.Background(), app)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if res.Status != task.StatusDone {
			t.Fatalf("status = %v, want done", res.Status)
		}
		if calls != 1 {
			t.Errorf("hakip2host invoked %d times, want 1", calls)
		}
		staged, _ := os.ReadFile(filepath.Join(workDir, "inputs", "resolved.dns.txt"))
		if !strings.Contains(string(staged), "host.example.com") {
			t.Errorf("reverse-IP host not staged; got:\n%s", string(staged))
		}
	})

	t.Run("disabled_skips_invocation", func(t *testing.T) {
		var calls int
		newStub(&calls)
		workDir := t.TempDir()
		app := internalTestApp(workDir, &stubBackend{stdout: dnsregs}, &scopeTree{patterns: []string{"*.example.com"}})
		app.Cfg.Subdomains.ReverseIP.Enabled = false

		tsk := SubDNSTask{}
		if _, err := tsk.Run(context.Background(), app); err != nil {
			t.Fatalf("Run: %v", err)
		}
		if calls != 0 {
			t.Errorf("hakip2host invoked %d times with ReverseIP disabled, want 0", calls)
		}
		staged, _ := os.ReadFile(filepath.Join(workDir, "inputs", "resolved.dns.txt"))
		if strings.Contains(string(staged), "host.example.com") {
			t.Errorf("reverse-IP host staged despite ReverseIP disabled")
		}
	})
}

// ExecOpts satisfies the backend.Backend options seam added in 18-01. It
// PRESERVES this fake's pre-18-01 dispatch exactly: Runner.Run used to call
// Backend.Exec and Runner.RunEnv used to call Backend.ExecEnv, and both now
// arrive here, so the env-set case forwards to ExecEnv and the zero case to Exec.
//
// It deliberately IGNORES opts.Stdin, opts.StdinPath and opts.Dir: this fake
// never receives them. A fake that needs to ASSERT on stdin must write its own
// ExecOpts instead of inheriting this forward — silently discarding the bytes is
// correct only because nothing here is testing them.
func (b *stubBackend) ExecOpts(ctx context.Context, t *backend.Tool, args []string, opts backend.ExecOptions) (*backend.Result, error) {
	if len(opts.Env) > 0 {
		return b.ExecEnv(ctx, t, args, opts.Env)
	}
	return b.Exec(ctx, t, args)
}

// StreamOpts satisfies the backend.Backend options seam (see ExecOpts).
func (b *stubBackend) StreamOpts(ctx context.Context, t *backend.Tool, args []string, opts backend.ExecOptions) (<-chan backend.Event, error) {
	if len(opts.Env) > 0 {
		return b.StreamEnv(ctx, t, args, opts.Env)
	}
	return b.Stream(ctx, t, args)
}

// -------------------------------------------------------------------------
// 18-01: hakip2host through the Runner seam (the plan's module leg)
// -------------------------------------------------------------------------

// TestReverseIPHostsDispatchesThroughTheRunnerSeam drives the DEFAULT
// hakip2hostRunner — not a stub — against a temp script registered as
// "hakip2host", proving three things at once:
//
//  1. the dispatch goes through backend.Runner (the script only runs if it does),
//  2. the newline-joined IP list reaches the tool's STANDARD INPUT, and
//  3. the invocation is RECORDED — hakip2host was invisible to logs/tools.jsonl
//     for its whole life.
//
// No DNS and no real hakip2host binary are involved.
func TestReverseIPHostsDispatchesThroughTheRunnerSeam(t *testing.T) {
	sh, err := os.Stat("/bin/sh")
	if err != nil || sh.IsDir() {
		t.Skip("skipping: /bin/sh unresolvable on this host")
	}

	dir := t.TempDir()
	stdinCopy := filepath.Join(dir, "stdin.txt")
	argvCopy := filepath.Join(dir, "argv.txt")
	script := filepath.Join(dir, "fake-hakip2host")

	// The script copies BOTH its stdin and its argv to disk, then emits a canned
	// PTR line. Asserting on the copies is asserting on what the PROCESS received.
	body := "#!/bin/sh\ncat > " + stdinCopy + "\nprintf '%s\\n' \"$*\" > " + argvCopy +
		"\necho '[PTR] 8.8.8.8 sub.example.com'\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil { //nolint:gosec // test-owned temp script
		t.Fatalf("writing the fake tool: %v", err)
	}

	recPath := filepath.Join(dir, "logs", "tools.jsonl")
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "hakip2host", Path: script})
	runner := backend.NewRunner(&backend.LocalBackend{}, reg, nil)
	runner.Recorder = backend.NewToolRecorder(recPath, nil)

	app := &appctx.AppContext{
		Tools:  runner,
		Tree:   &scopeTree{patterns: []string{"*.example.com"}},
		Target: &appctx.Target{Domain: "example.com", WorkDir: dir},
		Cfg:    &config.Config{},
	}

	got := reverseIPHosts(context.Background(), app, []string{"8.8.8.8", "1.1.1.1"})

	// (1) the parsed, in-scope result
	if len(got) != 1 || got[0] != "sub.example.com" {
		t.Errorf("reverseIPHosts = %v, want [sub.example.com]", got)
	}

	// (2) the IP list reached the tool's STDIN
	gotStdin, err := os.ReadFile(stdinCopy) //nolint:gosec // test-owned temp path
	if err != nil {
		t.Fatalf("the tool never read stdin (no copy written): %v", err)
	}
	if want := "8.8.8.8\n1.1.1.1\n"; string(gotStdin) != want {
		t.Errorf("stdin the process received = %q, want %q", gotStdin, want)
	}

	// (3) the invocation is now RECORDED
	raw, err := os.ReadFile(recPath) //nolint:gosec // test-owned temp path
	if err != nil {
		t.Fatalf("no recorder file — the dispatch bypassed the seam: %v", err)
	}
	if !strings.Contains(string(raw), `"hakip2host"`) {
		t.Errorf("hakip2host does not appear in the invocation record:\n%s", raw)
	}
}

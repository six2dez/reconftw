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
		hakip2hostRunner = func(_ context.Context, _ []string) (string, error) {
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

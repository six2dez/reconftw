// staging_lifecycle_test.go — F3 (phase 15, plan 15-13 Task 1) write-then-clear
// behaviour for the web producers, plus the end-to-end gate-3 experiment
// through web.MergeStage.
//
// The invariant under test, stated once:
//
//	A producer that RAN and found nothing REMOVES its own staging file, so the
//	merge cannot republish a previous run's results. A producer that did NOT run
//	never calls the helper at all, so its staging survives and resume still
//	merges its data.
//
// The end-to-end test drives MergeStage on "findings" DELIBERATELY. "findings"
// has no direct app.Tree.Append writer outside merge.go, so the MERGE owns the
// empty publish. It must NOT be written against fuzz, origins, urls or hosts:
// for those four the merge is barred from truncating (15-03's
// directArtefactWriterStages) and the empty publish belongs to their own direct
// writer instead — see artefact_publish_test.go.
//
// This file also hosts the shared web test doubles (webMockBackend, webMockTree)
// used by artefact_publish_test.go.
package web_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/core/task"
	"github.com/six2dez/reconftw/internal/modules/web"
)

// ---------------------------------------------------------------------------
// Shared test doubles
// ---------------------------------------------------------------------------

// webMockBackend is a configurable Backend double.
//
//   - execStdout / execErr drive Exec (used by app.Tools.Run).
//   - streamLines and streamErr drive Stream. streamErr is the TERMINAL error
//     carried on a final Event, i.e. "the tool RAN and ended badly"; it is NOT
//     the dispatch error. dispatchErr models "the binary is not on PATH" and is
//     returned by Stream() itself, which must stay task.StatusSkipped.
//   - onInvoke runs before events are produced, so a test can write the output
//     file a tool would have written via its -o/-oT flag.
type webMockBackend struct {
	execStdout  []byte
	execErr     error
	streamLines []string
	streamErr   error // terminal Event.Err — tool ran and exited non-zero
	dispatchErr error // Stream()'s own error — tool absent
	onInvoke    func(args []string)
	invocations int
}

func (m *webMockBackend) Exec(_ context.Context, _ *backend.Tool, args []string) (*backend.Result, error) {
	m.invocations++
	if m.onInvoke != nil {
		m.onInvoke(args)
	}
	if m.execErr != nil {
		return nil, m.execErr
	}
	return &backend.Result{Stdout: m.execStdout, ExitCode: 0}, nil
}

func (m *webMockBackend) Stream(_ context.Context, _ *backend.Tool, args []string) (<-chan backend.Event, error) {
	m.invocations++
	if m.dispatchErr != nil {
		return nil, m.dispatchErr
	}
	if m.onInvoke != nil {
		m.onInvoke(args)
	}
	ch := make(chan backend.Event, len(m.streamLines)+1)
	for _, l := range m.streamLines {
		ch <- backend.Event{Line: []byte(l)}
	}
	if m.streamErr != nil {
		ch <- backend.Event{Err: m.streamErr}
	}
	close(ch)
	return ch, nil
}

// ExecEnv / StreamEnv satisfy the Backend interface; the env channel is not
// exercised by any of the tasks under test, so they delegate (ADR §0 D-07: a
// nil env must behave byte-for-byte like the non-Env form).
func (m *webMockBackend) ExecEnv(ctx context.Context, t *backend.Tool, args, _ []string) (*backend.Result, error) {
	return m.Exec(ctx, t, args)
}

func (m *webMockBackend) StreamEnv(ctx context.Context, t *backend.Tool, args, _ []string) (<-chan backend.Event, error) {
	return m.Stream(ctx, t, args)
}

func (m *webMockBackend) HealthCheck(_ context.Context) error { return nil }
func (m *webMockBackend) Capacity() int                       { return 1 }

// newWebApp builds an AppContext with a real OutputTree over workDir and the
// named tools registered, so Runner's registry lookup succeeds.
func newWebApp(t *testing.T, workDir string, be *webMockBackend, tools ...string) *appctx.AppContext {
	t.Helper()
	scope := []string{"example.com", "*.example.com"}
	tree, err := output.NewTree(workDir, &output.DefaultScopeFilter{Patterns: scope})
	if err != nil {
		t.Fatalf("output.NewTree: %v", err)
	}
	reg := backend.NewToolRegistry()
	for _, name := range tools {
		reg.Register(&backend.Tool{Name: name})
	}
	cfg := &config.Config{}
	cfg.Web.WAF.Enabled = true
	cfg.Web.WellKnown = config.WebWellKnown{Enabled: true, MaxTargets: 200}
	return &appctx.AppContext{
		Tools:  backend.NewRunner(be, reg, nil),
		Tree:   tree,
		Cfg:    cfg,
		Target: &appctx.Target{Domain: "example.com", WorkDir: workDir, Scope: scope},
	}
}

// writeLinesFile writes newline-delimited content, creating parent dirs.
func writeLinesFile(t *testing.T, path string, lines ...string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", path, err)
	}
	body := ""
	if len(lines) > 0 {
		body = strings.Join(lines, "\n") + "\n"
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// countNonBlank counts non-blank lines. A missing file is FATAL: "present and
// empty" and "absent" are exactly the two states these tests distinguish, so a
// read helper may never conflate them.
func countNonBlank(t *testing.T, path string) int {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // test-controlled temp path
	if err != nil {
		t.Fatalf("file must EXIST (present-and-empty, not absent): %v", err)
	}
	n := 0
	for _, ln := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(ln) != "" {
			n++
		}
	}
	return n
}

func lookupWebTask(t *testing.T, name string) task.Task {
	t.Helper()
	tsk, ok := task.Default.Lookup(name)
	if !ok {
		t.Fatalf("%s not registered", name)
	}
	return tsk
}

// ---------------------------------------------------------------------------
// Write-then-clear, task 1 of 2: web.cdncheck (waf.cdncheck.jsonl)
// ---------------------------------------------------------------------------

// TestCdncheckStagingWriteThenClear is the two-run experiment on ONE stable
// workspace. Before this plan, cdncheck's zero-result path returned StatusDone
// BEFORE the staging write, so run A's CDN records stayed on disk for the waf
// merge to republish.
func TestCdncheckStagingWriteThenClear(t *testing.T) {
	workDir := t.TempDir()
	staging := filepath.Join(workDir, "inputs", "waf.cdncheck.jsonl")
	writeLinesFile(t, filepath.Join(workDir, "artefacts", "hosts.jsonl"),
		`{"host":"api.example.com","ip":"1.2.3.4"}`)

	// Run A — cdncheck classifies one IP.
	beA := &webMockBackend{execStdout: []byte("1.2.3.4 [cloudflare]\n")}
	appA := newWebApp(t, workDir, beA, "cdncheck")
	if _, err := lookupWebTask(t, "web.cdncheck").Run(context.Background(), appA); err != nil {
		t.Fatalf("run A: %v", err)
	}
	if got := countNonBlank(t, staging); got != 1 {
		t.Fatalf("run A: staging holds %d records, want 1", got)
	}

	// Run B — SAME workspace, cdncheck now classifies nothing.
	beB := &webMockBackend{execStdout: nil}
	appB := newWebApp(t, workDir, beB, "cdncheck")
	if _, err := lookupWebTask(t, "web.cdncheck").Run(context.Background(), appB); err != nil {
		t.Fatalf("run B: %v", err)
	}
	if _, err := os.Stat(staging); !os.IsNotExist(err) {
		body, _ := os.ReadFile(staging) //nolint:gosec // test-controlled temp path
		t.Errorf("run B classified nothing but %s survived — the waf merge would republish "+
			"run A's CDN records (F3); stat err = %v, contents = %q", staging, err, string(body))
	}
}

// TestCdncheckDidNotRunPreservesStaging is the other half: cdncheck with no IPs
// to classify returns StatusSkipped BEFORE the staging write, so a previous
// run's records must survive untouched.
func TestCdncheckDidNotRunPreservesStaging(t *testing.T) {
	workDir := t.TempDir()
	staging := filepath.Join(workDir, "inputs", "waf.cdncheck.jsonl")
	seed := `{"host":"1.2.3.4","cdn":"cloudflare","detected_by":"cdncheck"}`
	writeLinesFile(t, staging, seed)
	// hosts.jsonl exists but carries no ip field ⇒ readIPsFromHostsJSONL yields
	// nothing ⇒ StatusSkipped before any staging write.
	writeLinesFile(t, filepath.Join(workDir, "artefacts", "hosts.jsonl"),
		`{"host":"api.example.com"}`)

	be := &webMockBackend{}
	app := newWebApp(t, workDir, be, "cdncheck")
	res, err := lookupWebTask(t, "web.cdncheck").Run(context.Background(), app)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Status != task.StatusSkipped {
		t.Fatalf("status = %q, want skipped (no IPs to classify)", res.Status)
	}
	if be.invocations != 0 {
		t.Errorf("cdncheck must not have been invoked, got %d invocations", be.invocations)
	}
	got, err := os.ReadFile(staging) //nolint:gosec // test-controlled temp path
	if err != nil {
		t.Fatalf("a task that did NOT run must not clear its staging: %v", err)
	}
	if strings.TrimSpace(string(got)) != seed {
		t.Errorf("staging changed by a task that did not run: %q", string(got))
	}
}

// ---------------------------------------------------------------------------
// Write-then-clear, task 2 of 2: web.wellknown (hosts.wellknown.jsonl)
// ---------------------------------------------------------------------------

// TestWellknownStagingWriteThenClear drives the .well-known probe against an
// httptest server. Before this plan, "no in-scope hostnames discovered"
// returned StatusDone BEFORE the staging write, leaving run A's hostnames for
// the hosts merge.
func TestWellknownStagingWriteThenClear(t *testing.T) {
	workDir := t.TempDir()
	staging := filepath.Join(workDir, "inputs", "hosts.wellknown.jsonl")

	srvA := wellknownStub(t, "Contact: mailto:security@login.example.com\n")
	writeLinesFile(t, filepath.Join(workDir, "artefacts", "hosts.jsonl"),
		`{"url":"`+srvA+`","host":"127.0.0.1"}`)

	appA := newWebApp(t, workDir, &webMockBackend{})
	appA.Target.Scope = []string{"127.0.0.1", "*.example.com", "example.com"}
	if _, err := lookupWebTask(t, "web.wellknown").Run(context.Background(), appA); err != nil {
		t.Fatalf("run A: %v", err)
	}
	if got := countNonBlank(t, staging); got == 0 {
		t.Fatalf("run A: staging holds no hostnames, want at least 1")
	}

	// Run B — SAME workspace, the endpoint no longer advertises any hostname.
	srvB := wellknownStub(t, "Contact: mailto:nobody\n")
	writeLinesFile(t, filepath.Join(workDir, "artefacts", "hosts.jsonl"),
		`{"url":"`+srvB+`","host":"127.0.0.1"}`)
	appB := newWebApp(t, workDir, &webMockBackend{})
	appB.Target.Scope = []string{"127.0.0.1", "*.example.com", "example.com"}
	if _, err := lookupWebTask(t, "web.wellknown").Run(context.Background(), appB); err != nil {
		t.Fatalf("run B: %v", err)
	}
	if _, err := os.Stat(staging); !os.IsNotExist(err) {
		body, _ := os.ReadFile(staging) //nolint:gosec // test-controlled temp path
		t.Errorf("run B discovered nothing but %s survived — the hosts merge would republish "+
			"run A's hostnames (F3); stat err = %v, contents = %q", staging, err, string(body))
	}
}

// TestWellknownDidNotRunPreservesStaging: with no web targets the task returns
// StatusSkipped before any probe, so a previous run's staging must survive.
func TestWellknownDidNotRunPreservesStaging(t *testing.T) {
	workDir := t.TempDir()
	staging := filepath.Join(workDir, "inputs", "hosts.wellknown.jsonl")
	seed := `{"host":"login.example.com","tech":[]}`
	writeLinesFile(t, staging, seed)
	writeLinesFile(t, filepath.Join(workDir, "artefacts", "hosts.jsonl"))

	app := newWebApp(t, workDir, &webMockBackend{})
	res, err := lookupWebTask(t, "web.wellknown").Run(context.Background(), app)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Status != task.StatusSkipped {
		t.Fatalf("status = %q, want skipped (no web targets)", res.Status)
	}
	got, err := os.ReadFile(staging) //nolint:gosec // test-controlled temp path
	if err != nil {
		t.Fatalf("a task that did NOT run must not clear its staging: %v", err)
	}
	if strings.TrimSpace(string(got)) != seed {
		t.Errorf("staging changed by a task that did not run: %q", string(got))
	}
}

// ---------------------------------------------------------------------------
// End-to-end gate 3 — web.MergeStage("findings") owns the empty publish.
// ---------------------------------------------------------------------------

// TestGate3WebProducerToMergedFindings is acceptance gate 3 end to end for this
// package, driven through a real producer (web.arjun) into web.MergeStage:
// producer stages a finding → merge → artefact has 1 line; producer stages
// nothing → merge → artefact EXISTS with 0 lines.
//
// "findings" is used precisely because it has NO direct artefact writer, so the
// merge is the authoritative publisher and may safely empty the artefact.
func TestGate3WebProducerToMergedFindings(t *testing.T) {
	workDir := t.TempDir()
	artefact := filepath.Join(workDir, "artefacts", "findings.jsonl")
	writeLinesFile(t, filepath.Join(workDir, "artefacts", "urls.jsonl"),
		`{"url":"https://api.example.com/a?id=1"}`)

	runArjun := func(t *testing.T, outLines []string) *appctx.AppContext {
		t.Helper()
		be := &webMockBackend{onInvoke: func(args []string) {
			// arjun writes its results to the path given by -oT.
			for i, a := range args {
				if a == "-oT" && i+1 < len(args) {
					writeArjunOutput(t, args[i+1], outLines)
				}
			}
		}}
		app := newWebApp(t, workDir, be, "arjun")
		app.Cfg.Advanced.Deep = true
		if _, err := lookupWebTask(t, "web.arjun").Run(context.Background(), app); err != nil {
			t.Fatalf("arjun run: %v", err)
		}
		return app
	}

	// Run A — arjun finds one parameter endpoint.
	appA := runArjun(t, []string{"https://api.example.com/a?id=1"})
	if err := web.MergeStage(context.Background(), appA, "findings"); err != nil {
		t.Fatalf("run A MergeStage: %v", err)
	}
	if got := countNonBlank(t, artefact); got != 1 {
		t.Fatalf("run A: artefact holds %d findings, want 1", got)
	}

	// Run B — SAME workspace, arjun finds nothing.
	appB := runArjun(t, nil)
	if err := web.MergeStage(context.Background(), appB, "findings"); err != nil {
		t.Fatalf("run B MergeStage: %v", err)
	}
	if _, err := os.Stat(artefact); err != nil {
		t.Fatalf("artefact must EXIST and be empty, not be deleted: %v", err)
	}
	if got := countNonBlank(t, artefact); got != 0 {
		body, _ := os.ReadFile(artefact) //nolint:gosec // test-controlled temp path
		t.Errorf("run B found nothing but the artefact holds %d findings — a previous run's "+
			"findings were republished (F3, gate 3): %q", got, string(body))
	}
}

// writeArjunOutput writes (or, for no lines, removes) arjun's -oT output file,
// modelling a tool that produces no output file at all when it finds nothing.
func writeArjunOutput(t *testing.T, path string, lines []string) {
	t.Helper()
	if len(lines) == 0 {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			t.Fatalf("remove %s: %v", path, err)
		}
		return
	}
	writeLinesFile(t, path, lines...)
}

// wellknownStub serves security.txt with the given body from a fresh httptest
// server and returns its base URL. All other .well-known paths 404.
func wellknownStub(t *testing.T, securityTxt string) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/security.txt", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(securityTxt))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

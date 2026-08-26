// nuclei_coverage_test.go — the coverage record, proven against a LOCAL fixture.
//
// EVERY network-touching test here binds LOOPBACK (httptest.NewServer) and
// scans nothing but itself. There is no third-party host anywhere in this file,
// by construction: the target URLs come from httptest's own listener address.
// T-17-05-04.
//
// The end-to-end test drives the REAL nuclei binary through the REAL
// backend.Runner and the production runNucleiGroup, against real template files
// copied out of the installed template tree. That is deliberate. The bug this
// phase exists to close survived a full green test suite precisely because every
// nuclei assertion in the repo ran against text somebody typed.

package web

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/output"
)

// ─────────────────────────────────────────────────────────────────────────────
// fixture helpers
// ─────────────────────────────────────────────────────────────────────────────

// oidcDocument carries every word both OIDC templates match on. Verbatim shape
// of a real .well-known/openid-configuration document, minus anything
// identifying: the host is "fixture.local" and resolves nowhere.
const oidcDocument = `{"issuer":"https://fixture.local",` +
	`"authorization_endpoint":"https://fixture.local/auth",` +
	`"token_endpoint":"https://fixture.local/token",` +
	`"userinfo_endpoint":"https://fixture.local/userinfo",` +
	`"jwks_uri":"https://fixture.local/certs"}`

// startOIDCFixture stands up a loopback HTTP server serving the OIDC discovery
// document at both paths keycloak-openid-config probes, and 404 elsewhere.
//
// httptest.NewServer binds 127.0.0.1 on a free port and is CONCURRENT. That
// second property is not incidental: python's single-threaded http.server wedges
// under nuclei's default bulk-size of 25 and produces a hang that looks exactly
// like the coverage bug under investigation.
func startOIDCFixture(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	serveOIDC := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(oidcDocument))
	}
	mux.HandleFunc("/.well-known/openid-configuration", serveOIDC)
	mux.HandleFunc("/auth/realms/master/.well-known/openid-configuration", serveOIDC)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse fixture URL %q: %v", srv.URL, err)
	}
	if h := u.Hostname(); h != "127.0.0.1" && h != "::1" {
		t.Fatalf("fixture bound to %q, which is NOT loopback — refusing to scan it (T-17-05-04)", h)
	}
	return srv
}

// oidcTemplateDir copies the two OIDC templates out of the installed template
// tree into a temp dir, so the scan under test loads exactly two templates and
// its request budget is knowable.
//
// Skips (loudly) when the templates are not installed: a coverage assertion
// against templates that are not there would assert nothing.
func oidcTemplateDir(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("SKIP: no home dir to locate nuclei-templates: %v", err)
	}
	sources := []string{
		filepath.Join(home, "nuclei-templates", "http", "technologies", "oidc-detect.yaml"),
		filepath.Join(home, "nuclei-templates", "http", "exposures", "configs", "keycloak-openid-config.yaml"),
	}
	dir := t.TempDir()
	for _, src := range sources {
		data, rErr := os.ReadFile(src) //nolint:gosec // fixed path under the user's template tree
		if rErr != nil {
			t.Logf("SKIP: template %s not installed: %v", src, rErr)
			t.Skip()
		}
		if wErr := os.WriteFile(filepath.Join(dir, filepath.Base(src)), data, 0o600); wErr != nil {
			t.Fatalf("copy %s: %v", src, wErr)
		}
	}
	return dir
}

// nucleiApp builds an AppContext wired to the REAL local backend with the real
// nuclei binary registered, or skips when nuclei is absent.
func nucleiApp(t *testing.T) (*appctx.AppContext, string) {
	t.Helper()
	binPath, err := exec.LookPath("nuclei")
	if err != nil {
		t.Logf("SKIP: nuclei absent from PATH (%v) — this test proves the coverage record "+
			"against the REAL binary and cannot be satisfied by a stub", err)
		t.Skip()
	}
	workdir := t.TempDir()
	tree, err := output.NewTree(workdir, nil)
	if err != nil {
		t.Fatalf("output.NewTree: %v", err)
	}
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{
		Name: "nuclei",
		Path: binPath,
		// -duc: the ProjectDiscovery update check reaches the network at startup.
		// A test must not, and 16-03 already established the flag as the way to
		// stop it.
		DefaultArgs: []string{"-duc"},
		Timeout:     4 * time.Minute,
	})
	app := &appctx.AppContext{
		Tree:   tree,
		Tools:  backend.NewRunner(backend.NewLocalBackend(0), reg, nil),
		Target: &appctx.Target{Domain: "fixture.local", WorkDir: workdir},
	}
	return app, workdir
}

// readCoverageRecords decodes <workdir>/logs/nuclei-coverage.jsonl.
func readCoverageRecords(t *testing.T, workdir string) []NucleiCoverage {
	t.Helper()
	path := filepath.Join(workdir, "logs", "nuclei-coverage.jsonl")
	data, err := os.ReadFile(path) //nolint:gosec // test-controlled temp path
	if err != nil {
		t.Fatalf("no coverage record at %s: %v\n"+
			"  A nuclei group that writes NO account of what it covered is the exact state\n"+
			"  the 2026-08-24 parity run was in when it was signed BLOCKED.", path, err)
	}
	var out []NucleiCoverage
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var rec NucleiCoverage
		if uErr := json.Unmarshal([]byte(line), &rec); uErr != nil {
			t.Fatalf("coverage line is not valid JSON: %v\n  line: %s", uErr, line)
		}
		out = append(out, rec)
	}
	return out
}

func mustInt(t *testing.T, p *int, field string) int {
	t.Helper()
	if p == nil {
		t.Fatalf("coverage record field %s is NULL (unknown).\n"+
			"  nuclei reported no accounting for it, which means the arg vector no longer\n"+
			"  asks for it. A run that cannot say how many templates it loaded is the\n"+
			"  defect this record exists to make impossible.", field)
	}
	return *p
}

// ─────────────────────────────────────────────────────────────────────────────
// the end-to-end tracer: one real nuclei run that accounts for itself
// ─────────────────────────────────────────────────────────────────────────────

// TestNucleiCoverageEndToEnd runs the production runNucleiGroup against a
// loopback OIDC fixture with the two real OIDC templates and asserts the
// workspace record answers: selected, loaded, planned, sent, dropped, matched.
func TestNucleiCoverageEndToEnd(t *testing.T) {
	app, workdir := nucleiApp(t)
	tplDir := oidcTemplateDir(t)
	srv := startOIDCFixture(t)

	inputsDir := filepath.Join(workdir, "inputs")
	artefactsDir := filepath.Join(workdir, "artefacts")
	if err := os.MkdirAll(artefactsDir, 0o750); err != nil {
		t.Fatalf("mkdir artefacts: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	findings, err := runNucleiGroup(ctx, app, "nuclei", []string{srv.URL},
		"info,low,medium,high,critical", 150, tplDir, nil, "normal", inputsDir, artefactsDir)
	if err != nil {
		t.Fatalf("runNucleiGroup: %v", err)
	}

	recs := readCoverageRecords(t, workdir)
	if len(recs) != 1 {
		t.Fatalf("want exactly 1 coverage record, got %d: %+v", len(recs), recs)
	}
	rec := recs[0]

	if rec.Schema != nucleiCoverageSchema {
		t.Errorf("schema = %q, want %q", rec.Schema, nucleiCoverageSchema)
	}
	if rec.Group != "normal" {
		t.Errorf("group = %q, want %q", rec.Group, "normal")
	}

	// The proxy declaration. Asserted here as well as in its own test, because
	// this is the record a human actually reads.
	if strings.TrimSpace(rec.ExecutionBasis) == "" {
		t.Error("execution_basis is EMPTY — the record states coverage numbers without " +
			"declaring that requests_sent is a proxy for execution")
	}
	if !strings.Contains(rec.ExecutionBasis, "PROXY") {
		t.Errorf("execution_basis does not name the proxy: %q", rec.ExecutionBasis)
	}

	loaded := mustInt(t, rec.TemplatesLoaded, "templates_loaded")
	if loaded != 2 {
		t.Errorf("templates_loaded = %d, want 2 (the fixture dir holds exactly two templates)", loaded)
	}
	selected := mustInt(t, rec.FilterSelected, "filter_selected")
	if selected != 2 {
		t.Errorf("filter_selected = %d, want 2 — `nuclei -tl` under the same filters "+
			"must select the same two templates the engine loaded", selected)
	}
	if rec.HostsSubmitted != 1 {
		t.Errorf("hosts_submitted = %d, want 1", rec.HostsSubmitted)
	}
	if seen := mustInt(t, rec.HostsSeenByEngine, "hosts_seen_by_engine"); seen != 1 {
		t.Errorf("hosts_seen_by_engine = %d, want 1", seen)
	}

	// oidc-detect declares max-request 1, keycloak-openid-config declares 2 →
	// three planned requests, and against a healthy fixture all three are sent.
	planned := mustInt(t, rec.RequestsPlanned, "requests_planned")
	sent := mustInt(t, rec.RequestsSent, "requests_sent")
	if planned != 3 {
		t.Errorf("requests_planned = %d, want 3 (oidc-detect 1 + keycloak-openid-config 2)", planned)
	}
	if sent != planned {
		t.Errorf("requests_sent = %d but requests_planned = %d — against a healthy loopback "+
			"fixture every planned request must actually go out; a gap here IS the coverage "+
			"hole this record was built to surface", sent, planned)
	}

	// THREE matches, not two: oidc-detect fires once, and keycloak-openid-config
	// fires at BOTH of the paths it probes because the fixture serves the OIDC
	// document at both. That is deliberate — a fixture that answered only the
	// first path would leave the second request untested, and "the second request
	// was never sent" is precisely the failure shape under investigation.
	if matched := mustInt(t, rec.Matched, "matched"); matched != 3 {
		t.Errorf("matched = %d, want 3 (oidc-detect x1 + keycloak-openid-config x2 paths)", matched)
	}
	if parsed := mustInt(t, rec.FindingsParsed, "findings_parsed"); parsed != len(findings) {
		t.Errorf("findings_parsed = %d but runNucleiGroup returned %d records", parsed, len(findings))
	}
	if len(findings) != 3 {
		t.Errorf("runNucleiGroup returned %d findings, want 3: %+v", len(findings), findings)
	}
	// Both OIDC template IDs — the two that went missing on 2026-08-24 — are
	// present by NAME, not just by count.
	seen := map[string]bool{}
	for _, f := range findings {
		seen[f.TemplateID] = true
	}
	for _, id := range []string{"oidc-detect", "keycloak-openid-config"} {
		if !seen[id] {
			t.Errorf("template %q produced no finding against a fixture that serves exactly "+
				"what it matches on", id)
		}
	}

	// Healthy run: nothing dropped. Known-and-zero, NOT unknown — the argv no
	// longer suppresses the notices, so the absence of a drop is an observation.
	if rec.HostsDropped == nil {
		t.Error("hosts_dropped is NULL on a healthy run. It must be a known 0: the whole " +
			"point of dropping -silent is that a run can now tell 'no host was dropped' " +
			"from 'I would not have been told'.")
	} else if *rec.HostsDropped != 0 {
		t.Errorf("hosts_dropped = %d, want 0 on a healthy fixture (detail: %+v)",
			*rec.HostsDropped, rec.HostsDroppedDetail)
	}

	if rec.TerminatedEarly {
		t.Errorf("terminated_early = true on a clean run: %q", rec.TerminationError)
	}

	// The argv is IN the record, because the whole question is which flags
	// shaped the coverage.
	argv := strings.Join(rec.Argv, " ")
	for _, want := range []string{"-stats", "-sj", "-si", "-severity", "-rl"} {
		if !strings.Contains(argv, want) {
			t.Errorf("recorded argv is missing %s: %s", want, argv)
		}
	}
	if strings.Contains(argv, "-silent") {
		t.Errorf("recorded argv still carries -silent, which suppresses the per-host "+
			"drop notices this record needs: %s", argv)
	}

	pretty, _ := json.MarshalIndent(rec, "", "  ")
	t.Logf("COVERAGE RECORD (%s):\n%s", filepath.Join(workdir, "logs", "nuclei-coverage.jsonl"), pretty)
}

// TestNucleiCoverageRecordsHostDrops proves the per-host error budget is now
// VISIBLE. Two of the three fixture hosts point at closed loopback ports, and
// -mhe is forced to 1 via extraArgs so the budget is reached deterministically.
//
// This is the observation the 2026-08-24 run could not make: with -silent the
// skip notices are suppressed, and hosts_dropped would stay null.
func TestNucleiCoverageRecordsHostDrops(t *testing.T) {
	app, workdir := nucleiApp(t)
	tplDir := oidcTemplateDir(t)
	srv := startOIDCFixture(t)

	// Two loopback ports with nothing listening. Obtained by opening and
	// immediately closing a listener, so the ports are known-free and known-local.
	closed := make([]string, 0, 2)
	for i := 0; i < 2; i++ {
		l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("reserve closed port: %v", err)
		}
		addr := l.Addr().String()
		_ = l.Close()
		closed = append(closed, "http://"+addr)
	}

	inputsDir := filepath.Join(workdir, "inputs")
	artefactsDir := filepath.Join(workdir, "artefacts")
	if err := os.MkdirAll(artefactsDir, 0o750); err != nil {
		t.Fatalf("mkdir artefacts: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	hosts := append([]string{srv.URL}, closed...)
	_, _ = runNucleiGroup(ctx, app, "nuclei", hosts,
		"info,low,medium,high,critical", 150, tplDir, []string{"-mhe", "1"},
		"normal", inputsDir, artefactsDir)

	recs := readCoverageRecords(t, workdir)
	if len(recs) != 1 {
		t.Fatalf("want 1 coverage record, got %d", len(recs))
	}
	rec := recs[0]

	if rec.HostsDropped == nil {
		t.Fatal("hosts_dropped is NULL while two of three hosts are closed ports.\n" +
			"  This is the 2026-08-24 state exactly: nuclei DID stop scanning hosts and the\n" +
			"  run had no record of it, because -silent suppressed the notice.")
	}
	if *rec.HostsDropped == 0 {
		t.Fatalf("hosts_dropped = 0 with two closed-port hosts and -mhe 1; detail=%+v", rec.HostsDroppedDetail)
	}
	for _, d := range rec.HostsDroppedDetail {
		if strings.TrimSpace(d.Reason) == "" {
			t.Errorf("host %q was dropped with an EMPTY reason — 'which hosts and WHY' is "+
				"the requirement, and a drop with no cause is half an answer", d.Host)
		}
	}
	t.Logf("hosts_dropped=%d detail=%+v", *rec.HostsDropped, rec.HostsDroppedDetail)
}

// TestNucleiCoverageWrittenOnTerminatedGroup proves a group whose stream ends
// badly STILL writes its record, marked terminated.
//
// A stub `nuclei` that emits one stats object on stderr and exits 7 reproduces
// the shape without needing a way to crash the real binary on demand.
func TestNucleiCoverageWrittenOnTerminatedGroup(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skipf("SKIP: POSIX shell required for the stub tool: %v", err)
	}
	workdir := t.TempDir()
	if _, err := output.NewTree(workdir, nil); err != nil {
		t.Fatalf("output.NewTree: %v", err)
	}

	stub := filepath.Join(t.TempDir(), "nuclei")
	body := "#!/bin/sh\n" +
		`echo '{"duration":"0:00:01","errors":"4","hosts":"2","matched":"0","percent":"12",` +
		`"requests":"120","rps":"9","startedAt":"2026-08-25T10:00:00Z","templates":"9000","total":"1000"}' >&2` + "\n" +
		"exit 7\n"
	if err := os.WriteFile(stub, []byte(body), 0o700); err != nil { //nolint:gosec // test stub must be executable
		t.Fatalf("write stub: %v", err)
	}
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "nuclei", Path: stub})
	app := &appctx.AppContext{
		Tools:  backend.NewRunner(backend.NewLocalBackend(0), reg, nil),
		Target: &appctx.Target{Domain: "fixture.local", WorkDir: workdir},
	}

	inputsDir := filepath.Join(workdir, "inputs")
	artefactsDir := filepath.Join(workdir, "artefacts")
	for _, d := range []string{inputsDir, artefactsDir} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}

	_, err := runNucleiGroup(context.Background(), app, "nuclei",
		[]string{"http://127.0.0.1:1", "http://127.0.0.1:2"},
		"info", 150, t.TempDir(), nil, "waf", inputsDir, artefactsDir)
	if err == nil {
		t.Fatal("want a terminal stream error from a stub that exits 7, got nil")
	}

	recs := readCoverageRecords(t, workdir)
	if len(recs) != 1 {
		t.Fatalf("want 1 coverage record for the terminated group, got %d", len(recs))
	}
	rec := recs[0]
	if !rec.TerminatedEarly {
		t.Error("terminated_early = false for a group whose stream ended badly.\n" +
			"  Coverage evidence about a FAILED run is worth more than evidence about a\n" +
			"  clean one; this is the path on which v2 previously recorded nothing at all.")
	}
	if strings.TrimSpace(rec.TerminationError) == "" {
		t.Error("termination_error is empty on a terminated group")
	}
	// The accounting observed before the failure survives.
	if got := mustInt(t, rec.TemplatesLoaded, "templates_loaded"); got != 9000 {
		t.Errorf("templates_loaded = %d, want 9000 — the stats seen before the failure must survive", got)
	}
	if sent, planned := mustInt(t, rec.RequestsSent, "requests_sent"),
		mustInt(t, rec.RequestsPlanned, "requests_planned"); sent >= planned {
		t.Errorf("requests_sent=%d requests_planned=%d — the stub reports a partial run", sent, planned)
	}
	if rec.Group != "waf" {
		t.Errorf("group = %q, want waf", rec.Group)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// the declaration, and unknown-is-not-zero
// ─────────────────────────────────────────────────────────────────────────────

// TestNucleiCoverageProxyDeclarationEnforced fails if the execution-basis field
// can be dropped. A declaration nothing enforces is a comment, and this phase
// has spent two plans removing comments that asserted things the code did not do.
func TestNucleiCoverageProxyDeclarationEnforced(t *testing.T) {
	cov := newNucleiCoverage("normal", 3, []string{"-l", "hosts.txt"})
	if err := cov.Validate(); err != nil {
		t.Fatalf("a freshly constructed record must validate: %v", err)
	}
	if !strings.Contains(cov.ExecutionBasis, "PROXY") {
		t.Errorf("execution_basis does not name the proxy: %q", cov.ExecutionBasis)
	}
	if !strings.Contains(cov.ExecutionBasis, "Per-template execution") {
		t.Errorf("execution_basis does not state that per-template execution is unbounded "+
			"in a production run: %q", cov.ExecutionBasis)
	}

	cov.ExecutionBasis = ""
	if err := cov.Validate(); err == nil {
		t.Fatal("Validate() accepted a record with an EMPTY execution_basis")
	}
	cov.ExecutionBasis = "   "
	if err := cov.Validate(); err == nil {
		t.Fatal("Validate() accepted a whitespace-only execution_basis")
	}

	// And the writer refuses it, so an undeclared record cannot reach the disk.
	cov.ExecutionBasis = ""
	workdir := t.TempDir()
	if err := writeNucleiCoverage(workdir, cov); err == nil {
		t.Fatal("writeNucleiCoverage wrote a record with no proxy declaration")
	}
	if _, err := os.Stat(filepath.Join(workdir, "logs", "nuclei-coverage.jsonl")); err == nil {
		t.Fatal("an undeclared record reached the workspace file")
	}
}

// TestNucleiCoverageUnknownIsNotZero pins T-17-05-01: a count nuclei did not
// report must serialise as null, never 0.
func TestNucleiCoverageUnknownIsNotZero(t *testing.T) {
	// Built with `-silent` in the argv: under -silent nuclei suppresses the
	// per-host skip notices, so hosts_dropped is genuinely UNKNOWN too.
	cov := newNucleiCoverage("normal", 2, []string{"-silent"})
	for name, p := range map[string]*int{
		"filter_selected":      cov.FilterSelected,
		"templates_loaded":     cov.TemplatesLoaded,
		"hosts_seen_by_engine": cov.HostsSeenByEngine,
		"requests_planned":     cov.RequestsPlanned,
		"requests_sent":        cov.RequestsSent,
		"matched":              cov.Matched,
		"hosts_dropped":        cov.HostsDropped,
	} {
		if p != nil {
			t.Errorf("%s starts at %d; an unobserved count must start UNKNOWN (nil)", name, *p)
		}
	}

	b, err := json.Marshal(cov)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var raw map[string]json.RawMessage
	if uErr := json.Unmarshal(b, &raw); uErr != nil {
		t.Fatalf("unmarshal: %v", uErr)
	}
	for _, k := range []string{"templates_loaded", "requests_sent", "hosts_dropped", "filter_selected"} {
		v, ok := raw[k]
		if !ok {
			t.Fatalf("%s is missing from the record entirely — a reader cannot tell it was unknown", k)
		}
		if string(v) != "null" {
			t.Errorf("%s serialised as %s, want null.\n"+
				"  Reporting 0 where the record means UNKNOWN reproduces this phase's entire\n"+
				"  defect class inside its own remedy.", k, string(v))
		}
	}

	// A stats object with a non-numeric value leaves the field UNKNOWN rather
	// than defaulting it to zero.
	cov.observeLine([]byte(`{"templates":"","hosts":"2","requests":"nope","total":"9","matched":"0","errors":"0"}`), true)
	if cov.TemplatesLoaded != nil {
		t.Errorf("an empty templates value produced %d instead of UNKNOWN", *cov.TemplatesLoaded)
	}

	// THE OTHER HALF OF THE SAME DISTINCTION. Without -silent the notices are
	// observable, so a run that saw none has OBSERVED zero drops. A record that
	// could only ever say null would be just as useless as one that could only
	// ever say 0 — the point is that the two are different and the argv decides
	// which one is true.
	observable := newNucleiCoverage("normal", 2, []string{"-stats", "-sj"})
	if observable.HostsDropped == nil {
		t.Fatal("hosts_dropped is UNKNOWN under an argv that does NOT suppress the skip notices; " +
			"it must be an observed 0")
	}
	if *observable.HostsDropped != 0 {
		t.Errorf("hosts_dropped = %d before any notice was seen, want 0", *observable.HostsDropped)
	}
}

// TestNucleiCoverageParsesRealStatsLine decodes the exact stderr line nuclei
// v3.7.1 emits. Every value in it is a STRING, including the numbers — decoding
// them as int silently fails the whole line, which is the httpxRaw.Port shape
// that emptied the web layer for two months.
func TestNucleiCoverageParsesRealStatsLine(t *testing.T) {
	const real = `{"duration":"0:00:00","errors":"8","hosts":"3","matched":"2","percent":"100",` +
		`"requests":"9","rps":"35","startedAt":"2026-08-25T12:01:22.507752+02:00","templates":"2","total":"9"}`
	cov := newNucleiCoverage("normal", 3, nil)
	cov.observeLine([]byte(real), true)

	for _, c := range []struct {
		name string
		got  *int
		want int
	}{
		{"templates_loaded", cov.TemplatesLoaded, 2},
		{"hosts_seen_by_engine", cov.HostsSeenByEngine, 3},
		{"requests_sent", cov.RequestsSent, 9},
		{"requests_planned", cov.RequestsPlanned, 9},
		{"request_errors", cov.RequestErrors, 8},
		{"matched", cov.Matched, 2},
	} {
		if c.got == nil {
			t.Errorf("%s stayed UNKNOWN against a real nuclei stats line", c.name)
			continue
		}
		if *c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, *c.got, c.want)
		}
	}

	// A LATER stats object supersedes an earlier one — nuclei emits one per
	// interval and the final one at scan end is the complete account.
	cov.observeLine([]byte(`{"duration":"0:01:00","errors":"9","hosts":"3","matched":"4",`+
		`"percent":"100","requests":"40","rps":"1","startedAt":"x","templates":"2","total":"40"}`), true)
	if *cov.RequestsSent != 40 {
		t.Errorf("requests_sent = %d after a second stats object, want 40", *cov.RequestsSent)
	}

	// A stats object arriving on STDOUT is ignored: stdout carries findings and
	// a finding line must never be mistaken for accounting.
	cov.observeLine([]byte(`{"templates":"1","hosts":"1","requests":"1","total":"1","matched":"1","errors":"0"}`), false)
	if *cov.RequestsSent != 40 {
		t.Errorf("a stdout line mutated the accounting: requests_sent = %d", *cov.RequestsSent)
	}
}

// TestNucleiCoverageParsesRealSkipNotice decodes the exact stderr notice nuclei
// v3.7.1 emits when the per-host error budget removes a host. Both real shapes
// are covered: the first carries `cause=` directly, the second carries a Get
// error before it.
func TestNucleiCoverageParsesRealSkipNotice(t *testing.T) {
	lines := []string{
		`[INF] Skipped 127.0.0.1:18799 from target list as found unresponsive permanently: ` +
			`cause="port closed or filtered" address=127.0.0.1:18799 chain="connection refused; ` +
			`got err while executing http://127.0.0.1:18799/.well-known/openid-configuration"`,
		`[INF] Skipped 127.0.0.1:18798 from target list as found unresponsive permanently: ` +
			`Get "http://127.0.0.1:18798/.well-known/openid-configuration": cause="port closed or filtered" ` +
			`address=127.0.0.1:18798 chain="connection refused"`,
	}
	cov := newNucleiCoverage("normal", 3, nil)
	for _, l := range lines {
		cov.observeLine([]byte(l), true)
	}
	if cov.HostsDropped == nil {
		t.Fatal("hosts_dropped stayed UNKNOWN against two real skip notices")
	}
	if *cov.HostsDropped != 2 {
		t.Fatalf("hosts_dropped = %d, want 2", *cov.HostsDropped)
	}
	wantHosts := []string{"127.0.0.1:18799", "127.0.0.1:18798"}
	for i, d := range cov.HostsDroppedDetail {
		if d.Host != wantHosts[i] {
			t.Errorf("drop[%d].host = %q, want %q", i, d.Host, wantHosts[i])
		}
		if !strings.Contains(d.Reason, "port closed or filtered") {
			t.Errorf("drop[%d].reason lost nuclei's stated cause: %q", i, d.Reason)
		}
	}
}

// TestNucleiCoverageParsesRealTemplateList decodes real `nuclei -tl` stdout,
// including its blank line and its "Listing available ..." header.
func TestNucleiCoverageParsesRealTemplateList(t *testing.T) {
	const real = "\nListing available v10.4.8 nuclei templates for /Users/x/nuclei-templates\n" +
		"/tmp/tpl/keycloak-openid-config.yaml\n/tmp/tpl/oidc-detect.yaml\n"
	got := parseNucleiTemplateList([]byte(real))
	if got == nil {
		t.Fatal("parseNucleiTemplateList returned UNKNOWN for real -tl output")
	}
	if *got != 2 {
		t.Errorf("filter_selected = %d, want 2 (the header line must not be counted)", *got)
	}

	// Header-only output means the listing produced nothing usable. That is
	// UNKNOWN, not "the filter selected zero templates" — different facts,
	// different remedies.
	if p := parseNucleiTemplateList([]byte("\nListing available v10.4.8 nuclei templates for /x\n")); p != nil {
		t.Errorf("a listing with no template paths reported %d instead of UNKNOWN", *p)
	}
}

// TestNucleiCoverageRecordStaysSmall pins T-17-05-06: the accounting interval
// must not flood the workspace. One record per group per run, and the record is
// a single bounded JSON line whatever the stats volume.
func TestNucleiCoverageRecordStaysSmall(t *testing.T) {
	cov := newNucleiCoverage("normal", 12, []string{"-l", "h.txt", "-stats", "-sj", "-si", "30"})
	// A 4-hour run at -si 30 emits 480 stats objects. Every one is folded into
	// the same record.
	for i := 0; i < 480; i++ {
		cov.observeLine([]byte(`{"duration":"1:00:00","errors":"3","hosts":"12","matched":"49",`+
			`"percent":"50","requests":"120000","rps":"120","startedAt":"x","templates":"13143","total":"250000"}`), true)
	}
	workdir := t.TempDir()
	if err := writeNucleiCoverage(workdir, cov); err != nil {
		t.Fatalf("write: %v", err)
	}
	info, err := os.Stat(filepath.Join(workdir, "logs", "nuclei-coverage.jsonl"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Size() > 4096 {
		t.Errorf("coverage file is %d bytes after 480 stats objects; the record must fold "+
			"them, not accumulate them", info.Size())
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("coverage file mode = %v, want 0600 — it names scanned hosts, same posture "+
			"as logs/tools.jsonl", info.Mode().Perm())
	}
}

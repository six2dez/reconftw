// spray_test.go — behavior tests for SprayTask (13-07 Task 1).
//
// Internal (package vulns) so the tests override the unexported brutusRunner
// seam and exercise unexported parse helpers (parseBrutesprayHits,
// parseBrutusHits). A name-dispatching fake backend records the exact arg
// vectors passed to brutespray/nerva so argument fidelity is asserted without a
// real binary; the brutus stdin seam is stubbed via the brutusRunner package var.
//
// Coverage (plan 13-07 Task 1 behavior spec):
//   - identity (Name/Module/Enabled)
//   - gating: IP target / no-gnmap / deep-gate → StatusSkipped (bash parity)
//   - brutespray arg vector + credential redaction (XCUT-07)
//   - brutus deep-gate + stdin arg vector + JSON redaction (XCUT-07)
//   - degrade: missing brutespray/brutus → StatusSkipped, never StatusErrored
package vulns

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/log"
	"github.com/six2dez/reconftw/internal/core/output"
)

// -------------------------------------------------------------------------
// Test doubles
// -------------------------------------------------------------------------

type sprayCall struct {
	tool string
	args []string
}

// sprayFakeBackend dispatches on tool name: returns canned stdout / error per
// tool and records every (tool, args) invocation for arg-vector assertions.
type sprayFakeBackend struct {
	mu     sync.Mutex
	calls  []sprayCall
	stdout map[string][]byte
	errs   map[string]error
}

func newSprayFakeBackend() *sprayFakeBackend {
	return &sprayFakeBackend{stdout: map[string][]byte{}, errs: map[string]error{}}
}

func (b *sprayFakeBackend) Exec(_ context.Context, t *backend.Tool, args []string) (*backend.Result, error) {
	b.mu.Lock()
	b.calls = append(b.calls, sprayCall{tool: t.Name, args: append([]string(nil), args...)})
	err := b.errs[t.Name]
	out := b.stdout[t.Name]
	b.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return &backend.Result{Stdout: out, ExitCode: 0}, nil
}

func (b *sprayFakeBackend) ExecEnv(ctx context.Context, t *backend.Tool, args []string, _ []string) (*backend.Result, error) {
	return b.Exec(ctx, t, args)
}

func (b *sprayFakeBackend) Stream(_ context.Context, _ *backend.Tool, _ []string) (<-chan backend.Event, error) {
	ch := make(chan backend.Event)
	close(ch)
	return ch, nil
}

func (b *sprayFakeBackend) StreamEnv(ctx context.Context, t *backend.Tool, args []string, _ []string) (<-chan backend.Event, error) {
	return b.Stream(ctx, t, args)
}

func (b *sprayFakeBackend) HealthCheck(_ context.Context) error { return nil }
func (b *sprayFakeBackend) Capacity() int                       { return 1 }

func (b *sprayFakeBackend) argsFor(name string) ([]string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, c := range b.calls {
		if c.tool == name {
			return c.args, true
		}
	}
	return nil, false
}

func (b *sprayFakeBackend) called(name string) bool {
	_, ok := b.argsFor(name)
	return ok
}

// newSprayTestApp builds a minimal AppContext with the spray tools registered.
func newSprayTestApp(t *testing.T, be backend.Backend, cfg *config.Config) *appctx.AppContext {
	t.Helper()
	reg := backend.NewToolRegistry()
	for _, name := range []string{"brutespray", "nerva"} {
		reg.Register(&backend.Tool{Name: name})
	}
	return &appctx.AppContext{
		Tools:  backend.NewRunner(be, reg, nil),
		Target: &appctx.Target{Domain: "example.com", WorkDir: t.TempDir()},
		Cfg:    cfg,
	}
}

// sprayTestCfg returns a config with a populated Vulns.Spray block.
func sprayTestCfg() *config.Config {
	cfg := &config.Config{}
	cfg.Vulns.Spray = config.VulnSpray{Enabled: true, Engine: "brutespray", DeepOnly: true}
	cfg.Advanced.Tools.Brutespray = config.AdvToolBrutespray{Concurrence: 8}
	return cfg
}

// writeGnmapFixture copies the committed gnmap fixture into WorkDir/hosts/.
func writeGnmapFixture(t *testing.T, app *appctx.AppContext) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "fixtures", "spray", "portscan_active.gnmap"))
	if err != nil {
		t.Fatalf("read gnmap fixture: %v", err)
	}
	hostsDir := filepath.Join(app.Target.WorkDir, "hosts")
	if err := os.MkdirAll(hostsDir, 0o755); err != nil {
		t.Fatalf("mkdir hosts: %v", err)
	}
	if err := os.WriteFile(filepath.Join(hostsDir, "portscan_active.gnmap"), data, 0o644); err != nil {
		t.Fatalf("write gnmap: %v", err)
	}
}

// writeServiceFPFixture copies the committed service-fp fixture into WorkDir/hosts/.
func writeServiceFPFixture(t *testing.T, app *appctx.AppContext) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "fixtures", "spray", "service_fingerprints.jsonl"))
	if err != nil {
		t.Fatalf("read service-fp fixture: %v", err)
	}
	hostsDir := filepath.Join(app.Target.WorkDir, "hosts")
	if err := os.MkdirAll(hostsDir, 0o755); err != nil {
		t.Fatalf("mkdir hosts: %v", err)
	}
	if err := os.WriteFile(filepath.Join(hostsDir, "service_fingerprints.jsonl"), data, 0o644); err != nil {
		t.Fatalf("write service-fp: %v", err)
	}
}

// readFindings returns the contents of inputs/findings.spray.jsonl (or "").
func readFindings(t *testing.T, app *appctx.AppContext) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(app.Target.WorkDir, "inputs", "findings.spray.jsonl"))
	if err != nil {
		return ""
	}
	return string(data)
}

// -------------------------------------------------------------------------
// Identity
// -------------------------------------------------------------------------

func TestSprayTaskIdentity(t *testing.T) {
	task := &SprayTask{}
	if task.Name() != "vulns.spray" {
		t.Errorf("Name() = %q, want vulns.spray", task.Name())
	}
	if task.Module() != "vulns" {
		t.Errorf("Module() = %q, want vulns", task.Module())
	}
	if task.DependsOn() != nil {
		t.Errorf("DependsOn() = %v, want nil (reads web portscan workspace files)", task.DependsOn())
	}
	cfg := sprayTestCfg()
	if !task.Enabled(cfg) {
		t.Error("Enabled() = false with Spray.Enabled=true")
	}
	cfg.Vulns.Spray.Enabled = false
	if task.Enabled(cfg) {
		t.Error("Enabled() = true with Spray.Enabled=false")
	}
}

// -------------------------------------------------------------------------
// Gating (bash parity)
// -------------------------------------------------------------------------

func TestSprayGateIPTarget(t *testing.T) {
	be := newSprayFakeBackend()
	cfg := sprayTestCfg()
	cfg.Advanced.Deep = true
	app := newSprayTestApp(t, be, cfg)
	app.Target.IsIP = true
	writeGnmapFixture(t, app) // gnmap present — IP gate must still skip

	res, err := (&SprayTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Status != "skipped" {
		t.Errorf("Status = %q, want skipped (IP target)", res.Status)
	}
	if be.called("brutespray") {
		t.Error("brutespray invoked on IP target — must skip")
	}
}

func TestSprayGateNoGnmap(t *testing.T) {
	be := newSprayFakeBackend()
	cfg := sprayTestCfg()
	cfg.Advanced.Deep = true
	app := newSprayTestApp(t, be, cfg) // no gnmap written

	res, err := (&SprayTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Status != "skipped" {
		t.Errorf("Status = %q, want skipped (no gnmap)", res.Status)
	}
	if be.called("brutespray") {
		t.Error("brutespray invoked without gnmap — must skip")
	}
}

func TestSprayGateDeepOnly(t *testing.T) {
	be := newSprayFakeBackend()
	cfg := sprayTestCfg() // DeepOnly=true
	cfg.Advanced.Deep = false
	app := newSprayTestApp(t, be, cfg)
	writeGnmapFixture(t, app)

	res, err := (&SprayTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Status != "skipped" {
		t.Errorf("Status = %q, want skipped (deep-gated)", res.Status)
	}
	if be.called("brutespray") {
		t.Error("brutespray invoked without --deep while DeepOnly=true — must skip")
	}
}

// -------------------------------------------------------------------------
// brutespray (default engine)
// -------------------------------------------------------------------------

func TestSprayBrutesprayArgVectorAndRedaction(t *testing.T) {
	be := newSprayFakeBackend()
	// brutespray success line carries a FAKE credential that must never persist.
	be.stdout["brutespray"] = []byte(
		"[+] ssh - Login Successful - 1.2.3.4:22 - admin:FAKESPRAYPASS_AAAA\n" +
			"[*] some noise line\n")
	cfg := sprayTestCfg()
	cfg.Advanced.Deep = true
	app := newSprayTestApp(t, be, cfg)
	writeGnmapFixture(t, app)

	res, err := (&SprayTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Status != "done" {
		t.Fatalf("Status = %q, want done", res.Status)
	}

	args, ok := be.argsFor("brutespray")
	if !ok {
		t.Fatal("brutespray not invoked")
	}
	joined := strings.Join(args, " ")
	// -f <gnmap> -T <concurrence> -o <dir>
	if !strings.Contains(joined, "-f ") || !strings.Contains(joined, "portscan_active.gnmap") {
		t.Errorf("brutespray args missing -f gnmap: %v", args)
	}
	if !argPairPresent(args, "-T", "8") {
		t.Errorf("brutespray args missing -T 8 (concurrence): %v", args)
	}
	if !hasArg(args, "-o") || !strings.Contains(joined, filepath.Join("vulns", "brutespray")) {
		t.Errorf("brutespray args missing -o vulns/brutespray: %v", args)
	}

	// XCUT-07: a finding is recorded but the raw credential is NEVER in the JSONL.
	findings := readFindings(t, app)
	if findings == "" {
		t.Fatal("expected a credential finding in inputs/findings.spray.jsonl")
	}
	if strings.Contains(findings, "FAKESPRAYPASS_AAAA") {
		t.Errorf("XCUT-07 VIOLATION: raw credential leaked into findings:\n%s", findings)
	}
	if !strings.Contains(findings, `"payload_redacted":"***"`) {
		t.Errorf("finding missing payload_redacted=*** : %s", findings)
	}
	if !strings.Contains(findings, "1.2.3.4:22") {
		t.Errorf("finding should retain host:port target: %s", findings)
	}
	if !strings.Contains(findings, `"engine":"brutespray"`) {
		t.Errorf("finding missing engine=brutespray: %s", findings)
	}
}

func TestSprayBrutesprayDegradesWhenMissing(t *testing.T) {
	be := newSprayFakeBackend()
	be.errs["brutespray"] = context.DeadlineExceeded // stand-in for "tool unavailable/failed"
	cfg := sprayTestCfg()
	cfg.Advanced.Deep = true
	app := newSprayTestApp(t, be, cfg)
	writeGnmapFixture(t, app)

	res, err := (&SprayTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("Run returned error (must be best_effort, never errored): %v", err)
	}
	if res.Status == "errored" {
		t.Errorf("Status = errored; missing/failing brutespray must degrade (best_effort)")
	}
	if res.Status != "skipped" {
		t.Errorf("Status = %q, want skipped on brutespray failure", res.Status)
	}
}

// -------------------------------------------------------------------------
// brutus (deep-gated alternate engine, stdin seam)
// -------------------------------------------------------------------------

func TestSprayBrutusDeepGate(t *testing.T) {
	be := newSprayFakeBackend()
	cfg := sprayTestCfg()
	cfg.Vulns.Spray.Engine = "brutus"
	cfg.Advanced.Deep = false // not deep → brutus must skip
	app := newSprayTestApp(t, be, cfg)
	writeGnmapFixture(t, app)
	writeServiceFPFixture(t, app)

	brutusCalled := false
	restore := swapBrutusRunner(func(_ context.Context, _ string, _ []string) error {
		brutusCalled = true
		return nil
	})
	defer restore()

	res, err := (&SprayTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Status != "skipped" {
		t.Errorf("Status = %q, want skipped (brutus deep-gated, !deep)", res.Status)
	}
	if brutusCalled {
		t.Error("brutus invoked without --deep — must skip")
	}
}

func TestSprayBrutusStdinAndRedaction(t *testing.T) {
	be := newSprayFakeBackend()
	cfg := sprayTestCfg()
	cfg.Vulns.Spray.Engine = "brutus"
	cfg.Advanced.Deep = true
	cfg.Advanced.Tools.Brutus = config.AdvToolBrutus{Usernames: "/tmp/users.txt", Passwords: "/tmp/pass.txt"}
	app := newSprayTestApp(t, be, cfg)
	writeGnmapFixture(t, app)
	writeServiceFPFixture(t, app)

	var gotStdinPath string
	var gotArgs []string
	restore := swapBrutusRunner(func(_ context.Context, serviceFPPath string, args []string) error {
		gotStdinPath = serviceFPPath
		gotArgs = append([]string(nil), args...)
		// Emulate brutus writing a hit (with a FAKE credential) to its -o file.
		outPath := argValue(args, "-o")
		if outPath == "" {
			t.Fatal("brutus args missing -o output path")
		}
		return os.WriteFile(outPath,
			[]byte(`{"host":"1.2.3.4","port":22,"service":"ssh","username":"admin","password":"FAKEBRUTUSPASS_BBBB","success":true}`+"\n"),
			0o644)
	})
	defer restore()

	res, err := (&SprayTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Status != "done" {
		t.Fatalf("Status = %q, want done", res.Status)
	}

	// stdin carries the service-fingerprint JSON (13-03 artefact).
	if !strings.HasSuffix(gotStdinPath, filepath.Join("hosts", "service_fingerprints.jsonl")) {
		t.Errorf("brutus stdin path = %q, want hosts/service_fingerprints.jsonl", gotStdinPath)
	}
	// arg vector: --json -o vulns/brutus.jsonl -u <userfile> -p <passfile>
	joined := strings.Join(gotArgs, " ")
	if !hasArg(gotArgs, "--json") {
		t.Errorf("brutus args missing --json: %v", gotArgs)
	}
	if !strings.Contains(joined, filepath.Join("vulns", "brutus.jsonl")) {
		t.Errorf("brutus args missing -o vulns/brutus.jsonl: %v", gotArgs)
	}
	if !argPairPresent(gotArgs, "-u", "/tmp/users.txt") || !argPairPresent(gotArgs, "-p", "/tmp/pass.txt") {
		t.Errorf("brutus creds must cross as file paths -u/-p: %v", gotArgs)
	}

	// XCUT-07: finding recorded, raw brutus credential NEVER persisted.
	findings := readFindings(t, app)
	if findings == "" {
		t.Fatal("expected a credential finding for brutus")
	}
	if strings.Contains(findings, "FAKEBRUTUSPASS_BBBB") {
		t.Errorf("XCUT-07 VIOLATION: raw brutus credential leaked into findings:\n%s", findings)
	}
	if !strings.Contains(findings, `"engine":"brutus"`) {
		t.Errorf("finding missing engine=brutus: %s", findings)
	}
	if !strings.Contains(findings, "ssh 1.2.3.4:22") {
		t.Errorf("finding should retain service host:port: %s", findings)
	}
}

func TestSprayBrutusDegradesWhenMissing(t *testing.T) {
	be := newSprayFakeBackend()
	cfg := sprayTestCfg()
	cfg.Vulns.Spray.Engine = "brutus"
	cfg.Advanced.Deep = true
	app := newSprayTestApp(t, be, cfg)
	writeGnmapFixture(t, app)
	writeServiceFPFixture(t, app)

	restore := swapBrutusRunner(func(_ context.Context, _ string, _ []string) error {
		return errBrutusNotInstalled
	})
	defer restore()

	res, err := (&SprayTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("Run returned error (must be best_effort): %v", err)
	}
	if res.Status == "errored" {
		t.Errorf("Status = errored; missing brutus must degrade (best_effort)")
	}
}

func TestSprayBrutusSkipsWithoutServiceFP(t *testing.T) {
	be := newSprayFakeBackend()
	cfg := sprayTestCfg()
	cfg.Vulns.Spray.Engine = "brutus"
	cfg.Advanced.Deep = true
	app := newSprayTestApp(t, be, cfg)
	writeGnmapFixture(t, app) // gnmap present but NO service-fp and NO naabu_open.txt

	brutusCalled := false
	restore := swapBrutusRunner(func(_ context.Context, _ string, _ []string) error {
		brutusCalled = true
		return nil
	})
	defer restore()

	res, err := (&SprayTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Status != "skipped" {
		t.Errorf("Status = %q, want skipped (no service-fp input for brutus)", res.Status)
	}
	if brutusCalled {
		t.Error("brutus invoked without any service-fingerprint input — must skip")
	}
}

// -------------------------------------------------------------------------
// Unit tests for the redacting parsers
// -------------------------------------------------------------------------

func TestParseBrutesprayHitsRedacts(t *testing.T) {
	stdout := []byte("[+] mysql - Login Successful - 10.0.0.5:3306 - root:TOPSECRET_CCCC\nnoise\n")
	hits := parseBrutesprayHits(stdout)
	if len(hits) != 1 {
		t.Fatalf("got %d hits, want 1", len(hits))
	}
	if hits[0].PayloadRedacted != "***" || hits[0].PoCRedacted != "***" {
		t.Errorf("credential not redacted: %+v", hits[0])
	}
	if strings.Contains(hits[0].MatchedParam, "TOPSECRET_CCCC") {
		t.Errorf("credential leaked into MatchedParam: %q", hits[0].MatchedParam)
	}
	if !strings.Contains(hits[0].MatchedParam, "10.0.0.5:3306") {
		t.Errorf("host:port not retained: %q", hits[0].MatchedParam)
	}
}

func TestParseBrutusHitsRedacts(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "brutus.jsonl")
	if err := os.WriteFile(out, []byte(
		`{"host":"1.1.1.1","port":22,"service":"ssh","username":"admin","password":"SECRET_DDDD","success":true}`+"\n"+
			`{"ip":"2.2.2.2","port":21,"service":"ftp","success":false}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	hits := parseBrutusHits(out)
	if len(hits) != 1 {
		t.Fatalf("got %d hits, want 1 (success:false excluded)", len(hits))
	}
	if strings.Contains(hits[0].MatchedParam, "SECRET_DDDD") || hits[0].PayloadRedacted != "***" {
		t.Errorf("credential not redacted: %+v", hits[0])
	}
}

// TestSprayBrutusConfinesRawOutput proves the WR-13-03 secret-at-rest fix: after
// brutus writes its raw --json hit file (0644, carrying a live user:pass), the
// task (1) restricts it to owner-only 0600 and (2) registers the discovered
// credential with the log Redactor so a later log line echoing it is scrubbed.
// The redacted findings stream still carries only "***".
func TestSprayBrutusConfinesRawOutput(t *testing.T) {
	be := newSprayFakeBackend()
	cfg := sprayTestCfg()
	cfg.Vulns.Spray.Engine = "brutus"
	cfg.Advanced.Deep = true
	app := newSprayTestApp(t, be, cfg)
	writeGnmapFixture(t, app)
	writeServiceFPFixture(t, app)

	// Redacting logger so registration of the discovered credential is observable.
	buf := &bytes.Buffer{}
	app.Log = slog.New(log.NewRedactingHandler(
		slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}), &log.Redactor{}))

	const rawPass = "FAKEBRUTUSPASS_WR13_03"
	restore := swapBrutusRunner(func(_ context.Context, _ string, args []string) error {
		outPath := argValue(args, "-o")
		if outPath == "" {
			t.Fatal("brutus args missing -o output path")
		}
		// brutus writes the raw hit at world-readable 0644 — the exposure WR-13-03
		// closes. Note the file is created 0644 here; the task must tighten it.
		return os.WriteFile(outPath,
			[]byte(`{"host":"1.2.3.4","port":22,"service":"ssh","username":"operator","password":"`+rawPass+`","success":true}`+"\n"),
			0o644)
	})
	defer restore()

	if _, err := (&SprayTask{}).Run(context.Background(), app); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// (1) The raw brutus output file must be restricted to owner-only 0600.
	info, err := os.Stat(filepath.Join(app.Target.WorkDir, "vulns", "brutus.jsonl"))
	if err != nil {
		t.Fatalf("stat brutus.jsonl: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("brutus.jsonl perm = %04o, want 0600 (WR-13-03: not world-readable)", perm)
	}

	// (2) The discovered credential must be registered with the Redactor: logging
	// it now must emit "***", never the raw value.
	app.Log.Info("probe", "cred", rawPass)
	if strings.Contains(buf.String(), rawPass) {
		t.Fatalf("WR-13-03 VIOLATION: raw brutus credential not registered — leaked to logs:\n%s", buf.String())
	}

	// The redacted findings stream still carries only "***".
	if f := readFindings(t, app); strings.Contains(f, rawPass) {
		t.Fatalf("XCUT-07 VIOLATION: raw credential leaked into findings:\n%s", f)
	}
}

// -------------------------------------------------------------------------
// Small arg-vector helpers
// -------------------------------------------------------------------------

// swapBrutusRunner replaces the brutusRunner package var and returns a restore fn.
func swapBrutusRunner(fn func(context.Context, string, []string) error) func() {
	prev := brutusRunner
	brutusRunner = fn
	return func() { brutusRunner = prev }
}

func hasArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

func argPairPresent(args []string, flag, val string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag && args[i+1] == val {
			return true
		}
	}
	return false
}

func argValue(args []string, flag string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag {
			return args[i+1]
		}
	}
	return ""
}

// -------------------------------------------------------------------------
// F20 bullet 3 — shared-IP attribution (plan 15-14 Task 3)
// -------------------------------------------------------------------------

// TestSprayHostsByIPKeepsEveryHostname is the core of the F20 fix. Three
// unrelated names share 10.0.0.5, as they do on any shared-hosting address or
// CDN edge. The old index kept the FIRST one and discarded the rest, so a
// successful credential spray was filed against whichever name happened to be
// written to hosts.jsonl first.
func TestSprayHostsByIPKeepsEveryHostname(t *testing.T) {
	app := newSprayIndexApp(t,
		`{"host":"a.example.com","ip":"10.0.0.5"}`,
		`{"host":"b.example.com","ip":"10.0.0.5"}`,
		`{"host":"c.example.com","ip":"10.0.0.5"}`,
		// A duplicate must not appear twice.
		`{"host":"b.example.com","ip":"10.0.0.5"}`,
		`{"host":"solo.example.com","ip":"10.0.0.9"}`,
	)

	index := sprayHostsByIP(app)
	got := index["10.0.0.5"]
	want := []string{"a.example.com", "b.example.com", "c.example.com"}
	if len(got) != len(want) {
		t.Fatalf("10.0.0.5 → %v, want all three names in first-seen order (%v)", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("10.0.0.5 → %v, want first-seen order %v", got, want)
		}
	}
	if solo := index["10.0.0.9"]; len(solo) != 1 || solo[0] != "solo.example.com" {
		t.Fatalf("10.0.0.9 → %v, want exactly [solo.example.com]", solo)
	}
}

// TestSprayAmbiguousIPKeepsIPLocatorAndListsEveryHost is F20's behavioural
// assertion: with several names on the address the finding must NOT be
// attributed to any one of them. Filing a confirmed credential spray against
// the wrong domain sends a disclosure to a party with no relationship to the
// service.
func TestSprayAmbiguousIPKeepsIPLocatorAndListsEveryHost(t *testing.T) {
	app := newSprayIndexApp(t,
		`{"host":"a.example.com","ip":"10.0.0.5"}`,
		`{"host":"b.example.com","ip":"10.0.0.5"}`,
		`{"host":"c.example.com","ip":"10.0.0.5"}`,
	)

	got := sprayResolveScopeHosts(app, []VulnFindingRecord{
		{Host: "10.0.0.5", VulnClass: "credential-spray", Engine: "brutespray"},
	})

	if got[0].Host != "10.0.0.5" {
		t.Fatalf("Host = %q — a shared IP was attributed to ONE arbitrary hostname; the "+
			"spray result only supports the claim that the service lives at 10.0.0.5",
			got[0].Host)
	}
	want := []string{"a.example.com", "b.example.com", "c.example.com"}
	if len(got[0].Hostnames) != len(want) {
		t.Fatalf("Hostnames = %v, want all three candidates %v", got[0].Hostnames, want)
	}
	for i := range want {
		if got[0].Hostnames[i] != want[i] {
			t.Fatalf("Hostnames = %v, want first-seen order %v", got[0].Hostnames, want)
		}
	}
}

// TestSprayUnambiguousIPAdoptsTheSingleHostname documents the chosen
// single-hostname convention: exactly one name resolving to the address is not
// a guess, so Host BECOMES that hostname and Hostnames carries it as its single
// entry. This is also what keeps the finding in scope under a domain-only scope,
// which is why the original (over-broad) rewrite existed at all.
func TestSprayUnambiguousIPAdoptsTheSingleHostname(t *testing.T) {
	app := newSprayIndexApp(t, `{"host":"ssh.example.com","ip":"10.0.0.5"}`)

	got := sprayResolveScopeHosts(app, []VulnFindingRecord{
		{Host: "10.0.0.5", VulnClass: "credential-spray", Engine: "brutespray"},
	})
	if got[0].Host != "ssh.example.com" {
		t.Fatalf("Host = %q, want ssh.example.com — a single resolving name is unambiguous",
			got[0].Host)
	}
	if len(got[0].Hostnames) != 1 || got[0].Hostnames[0] != "ssh.example.com" {
		t.Fatalf("Hostnames = %v, want exactly [ssh.example.com]", got[0].Hostnames)
	}
}

// TestSprayUnmappableIPKeepsIPLocator — an address with no known name keeps the
// IP. Correct, not a fallback: under an IP or CIDR target scope the IP is
// exactly the right locator.
func TestSprayUnmappableIPKeepsIPLocator(t *testing.T) {
	app := newSprayIndexApp(t, `{"host":"ssh.example.com","ip":"10.0.0.5"}`)

	got := sprayResolveScopeHosts(app, []VulnFindingRecord{
		{Host: "192.0.2.9", VulnClass: "credential-spray"},
	})
	if got[0].Host != "192.0.2.9" {
		t.Fatalf("Host = %q, want the IP left alone", got[0].Host)
	}
	if len(got[0].Hostnames) != 0 {
		t.Fatalf("Hostnames = %v, want empty for an unmappable IP", got[0].Hostnames)
	}
}

// TestSprayIPLiteralSurvivesScopeGate is T-15-14-03. Keeping the IP as the
// locator is only correct if an IP-literal finding is actually ADMITTED for an
// in-scope address. Dropping credential-spray results at the scope boundary is
// the exact class of silent finding loss an earlier audit fixed, and
// reintroducing it here would be worse than the misattribution being repaired.
//
// The assertion is on a NON-ZERO kept count, not merely on the absence of an
// error.
func TestSprayIPLiteralSurvivesScopeGate(t *testing.T) {
	workDir := t.TempDir()
	// An operator scoped to the CIDR — the case where an IP locator is right.
	tree, err := output.NewTree(workDir, &output.DefaultScopeFilter{
		Patterns: []string{"10.0.0.0/24"},
	})
	if err != nil {
		t.Fatalf("output.NewTree: %v", err)
	}

	rec := VulnFindingRecord{
		Host:            "10.0.0.5",
		Hostnames:       []string{"a.example.com", "b.example.com"},
		Severity:        "critical",
		VulnClass:       "credential-spray",
		PayloadRedacted: "***",
		PoCRedacted:     "***",
		Engine:          "brutespray",
	}
	line, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	kept, dropped := output.FilterInScope(tree, "findings", [][]byte{line})
	if len(kept) == 0 {
		t.Fatalf("an IP-literal credential-spray finding was DROPPED at the scope gate "+
			"(dropped=%d) for an in-scope address — the highest-severity result the "+
			"pipeline can produce would vanish silently", dropped)
	}
}

// TestSprayAttributionKeepsCredentialRedacted — the F20 rewrite must not touch
// XCUT-07. No raw credential may appear in the record or in any log line
// produced while resolving attribution.
func TestSprayAttributionKeepsCredentialRedacted(t *testing.T) {
	const rawPassword = "Sup3rS3cret!"

	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	app := newSprayIndexApp(t,
		`{"host":"a.example.com","ip":"10.0.0.5"}`,
		`{"host":"b.example.com","ip":"10.0.0.5"}`,
	)
	app.Log = logger

	findings := parseBrutesprayHits([]byte(
		"[+] ssh - 10.0.0.5:22 - Login Successful - admin:" + rawPassword + "\n"))
	if len(findings) == 0 {
		t.Fatalf("fixture produced no spray finding — the parser changed shape")
	}
	got := sprayResolveScopeHosts(app, findings)

	body, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if bytes.Contains(body, []byte(rawPassword)) {
		t.Fatalf("XCUT-07 VIOLATION: the raw credential reached the finding record:\n%s", body)
	}
	if !bytes.Contains(body, []byte("***")) {
		t.Fatalf("the finding must carry the *** redaction marker:\n%s", body)
	}
	if strings.Contains(logBuf.String(), rawPassword) {
		t.Fatalf("XCUT-07 VIOLATION: the raw credential reached a log line:\n%s", logBuf.String())
	}
}

// TestSprayDeterminismCommentIsGone pins the removal of the comment that
// documented the F20 defect while presenting it as a feature ("the first host
// seen for an IP wins, keeping the result deterministic for shared IPs").
// Determinism is not correctness; a comment asserting otherwise is how the
// defect survived review.
func TestSprayDeterminismCommentIsGone(t *testing.T) {
	src, err := os.ReadFile("spray.go")
	if err != nil {
		t.Fatalf("read spray.go: %v", err)
	}
	body := string(src)
	if strings.Contains(body, "first host seen for an IP wins") {
		t.Errorf("spray.go still claims the first host seen for an IP wins — that comment " +
			"describes the F20 defect as if it were the design")
	}
	if strings.Contains(body, "mapped the service IP back to its in-scope host") {
		t.Errorf("spray.go still logs a claim the spray result does not support")
	}
	if !strings.Contains(body, "func sprayHostsByIP(app *appctx.AppContext) map[string][]string") {
		t.Errorf("sprayHostsByIP must return map[string][]string — one hostname per IP " +
			"cannot express a shared address")
	}
}

// newSprayIndexApp writes artefacts/hosts.jsonl with the given raw JSONL lines.
func newSprayIndexApp(t *testing.T, lines ...string) *appctx.AppContext {
	t.Helper()
	workDir := t.TempDir()
	dir := filepath.Join(workDir, "artefacts")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir artefacts: %v", err)
	}
	body := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "hosts.jsonl"), []byte(body), 0o644); err != nil {
		t.Fatalf("write hosts.jsonl: %v", err)
	}
	return &appctx.AppContext{
		Target: &appctx.Target{Domain: "example.com", WorkDir: workDir},
	}
}

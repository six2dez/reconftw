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
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
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

// portscan_test.go — behavior tests for WebPortscanTask (13-03 Task 1 + Task 2).
//
// Internal (package web) because the tests override the unexported
// shodanInternetDBGet seam and exercise unexported helpers (portscanNmapXMLURLs,
// portscanParseGnmap). A name-dispatching fake backend records the exact
// arg-vectors passed to each tool so the naabu/nmap/nerva argument fidelity
// (T-13-03-02/03) is asserted without a real binary.
package web

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

type portscanCall struct {
	tool string
	args []string
}

// fakeToolBackend dispatches on tool name: it returns canned stdout / error per
// tool and records every (tool, args) invocation for arg-vector assertions.
type fakeToolBackend struct {
	mu     sync.Mutex
	calls  []portscanCall
	stdout map[string][]byte
	errs   map[string]error
}

func newFakeToolBackend() *fakeToolBackend {
	return &fakeToolBackend{stdout: map[string][]byte{}, errs: map[string]error{}}
}

func (b *fakeToolBackend) Exec(_ context.Context, t *backend.Tool, args []string) (*backend.Result, error) {
	b.mu.Lock()
	b.calls = append(b.calls, portscanCall{tool: t.Name, args: append([]string(nil), args...)})
	err := b.errs[t.Name]
	out := b.stdout[t.Name]
	b.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return &backend.Result{Stdout: out, ExitCode: 0}, nil
}

func (b *fakeToolBackend) ExecEnv(ctx context.Context, t *backend.Tool, args []string, _ []string) (*backend.Result, error) {
	return b.Exec(ctx, t, args)
}

func (b *fakeToolBackend) Stream(_ context.Context, _ *backend.Tool, _ []string) (<-chan backend.Event, error) {
	ch := make(chan backend.Event)
	close(ch)
	return ch, nil
}

func (b *fakeToolBackend) StreamEnv(ctx context.Context, t *backend.Tool, args []string, _ []string) (<-chan backend.Event, error) {
	return b.Stream(ctx, t, args)
}

func (b *fakeToolBackend) HealthCheck(_ context.Context) error { return nil }
func (b *fakeToolBackend) Capacity() int                       { return 1 }

// argsFor returns the args of the first invocation of name.
func (b *fakeToolBackend) argsFor(name string) ([]string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, c := range b.calls {
		if c.tool == name {
			return c.args, true
		}
	}
	return nil, false
}

// countCalls returns how many times name was invoked.
func (b *fakeToolBackend) countCalls(name string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for _, c := range b.calls {
		if c.tool == name {
			n++
		}
	}
	return n
}

// newPortscanTestApp builds a minimal AppContext with the portscan tools
// registered (so Runner.Lookup succeeds) and a per-test WorkDir.
func newPortscanTestApp(t *testing.T, be backend.Backend, cfg *config.Config) *appctx.AppContext {
	t.Helper()
	reg := backend.NewToolRegistry()
	for _, name := range []string{"cdncheck", "smap", "naabu", "nmap", "nerva"} {
		reg.Register(&backend.Tool{Name: name})
	}
	return &appctx.AppContext{
		Tools:  backend.NewRunner(be, reg, nil),
		Target: &appctx.Target{Domain: "example.com", WorkDir: t.TempDir()},
		Cfg:    cfg,
	}
}

// portscanTestCfg returns a config with a fully-populated Web.Portscan block.
func portscanTestCfg() *config.Config {
	cfg := &config.Config{}
	cfg.Web.Portscan = config.WebPortscan{
		Enabled:        true,
		PassiveEnabled: true,
		ActiveEnabled:  true,
		Strategy:       "legacy",
		CDNCheck:       true,
		CDNBypass:      false,
		Naabu:          config.WebNaabu{Enabled: true, Rate: 1000, Ports: "--top-ports 1000"},
		ServiceFingerprint: config.WebServiceFingerprint{
			Enabled: true, Engine: "nerva", TimeoutMS: 2000,
		},
	}
	return cfg
}

// stubShodan overrides the keyless internetdb seam so unit tests never hit the
// network. Restored on cleanup.
func stubShodan(t *testing.T, fn func(ctx context.Context, ip string) ([]byte, error)) {
	t.Helper()
	orig := shodanInternetDBGet
	t.Cleanup(func() { shodanInternetDBGet = orig })
	shodanInternetDBGet = fn
}

func writeSubdomainsIPs(t *testing.T, app *appctx.AppContext, content string) {
	t.Helper()
	dir := filepath.Join(app.Target.WorkDir, "subdomains")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir subdomains: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "subdomains_ips.txt"), []byte(content), 0o644); err != nil {
		t.Fatalf("write subdomains_ips.txt: %v", err)
	}
}

func hasSubsequence(args []string, want ...string) bool {
	for i := 0; i+len(want) <= len(args); i++ {
		if slicesEqual(args[i:i+len(want)], want) {
			return true
		}
	}
	return false
}

func slicesEqual(a, b []string) bool {
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

func containsToken(args []string, tok string) bool {
	for _, a := range args {
		if a == tok {
			return true
		}
	}
	return false
}

// -------------------------------------------------------------------------
// Identity / Enabled
// -------------------------------------------------------------------------

func TestWebPortscanTaskIdentity(t *testing.T) {
	tsk := &WebPortscanTask{}
	if tsk.Name() != "web.portscan" {
		t.Errorf("Name() = %q, want web.portscan", tsk.Name())
	}
	if tsk.Module() != "web" {
		t.Errorf("Module() = %q, want web", tsk.Module())
	}
	if tsk.DependsOn() != nil {
		t.Errorf("DependsOn() = %v, want nil", tsk.DependsOn())
	}
	cfg := portscanTestCfg()
	if !tsk.Enabled(cfg) {
		t.Error("Enabled should be true when cfg.Web.Portscan.Enabled=true")
	}
	cfg.Web.Portscan.Enabled = false
	if tsk.Enabled(cfg) {
		t.Error("Enabled should be false when cfg.Web.Portscan.Enabled=false")
	}
}

// -------------------------------------------------------------------------
// Passive: smap output + CDN exclusion
// -------------------------------------------------------------------------

func TestWebPortscanPassive(t *testing.T) {
	stubShodan(t, func(context.Context, string) ([]byte, error) { return nil, os.ErrDeadlineExceeded })

	be := newFakeToolBackend()
	be.stdout["cdncheck"] = []byte("1.1.1.1 [cloudflare]\n") // 1.1.1.1 is CDN → excluded
	be.stdout["smap"] = []byte("Host: 8.8.8.8\n80/tcp open http\n")

	cfg := portscanTestCfg()
	cfg.Web.Portscan.ActiveEnabled = false // passive-only path
	app := newPortscanTestApp(t, be, cfg)
	writeSubdomainsIPs(t, app, "api.example.com - 8.8.8.8\ncdn.example.com - 1.1.1.1\n")

	res, err := (&WebPortscanTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Status != "done" {
		t.Fatalf("status = %v, want done", res.Status)
	}

	// portscan_passive.txt holds the smap output.
	passive, _ := os.ReadFile(filepath.Join(app.Target.WorkDir, "hosts", "portscan_passive.txt"))
	if !strings.Contains(string(passive), "80/tcp open http") {
		t.Errorf("portscan_passive.txt missing smap output; got:\n%s", passive)
	}

	// The non-CDN IP set excludes the CDN IP (1.1.1.1) and keeps 8.8.8.8.
	nocdn, _ := os.ReadFile(filepath.Join(app.Target.WorkDir, ".tmp", "ips_nocdn.txt"))
	if !strings.Contains(string(nocdn), "8.8.8.8") {
		t.Errorf("ips_nocdn.txt should contain 8.8.8.8; got:\n%s", nocdn)
	}
	if strings.Contains(string(nocdn), "1.1.1.1") {
		t.Errorf("ips_nocdn.txt should NOT contain CDN IP 1.1.1.1; got:\n%s", nocdn)
	}

	// smap was invoked with -iL <ips_nocdn>; active tools were NOT (ActiveEnabled=false).
	if _, ok := be.argsFor("smap"); !ok {
		t.Error("smap was not invoked in the passive path")
	}
	if be.countCalls("naabu") != 0 || be.countCalls("nmap") != 0 {
		t.Error("active tools invoked despite ActiveEnabled=false")
	}
}

// -------------------------------------------------------------------------
// Active: naabu_nmap strategy — arg vectors + naabu_open.txt + nmap targeting
// -------------------------------------------------------------------------

func TestWebPortscanActiveNaabuNmap(t *testing.T) {
	stubShodan(t, func(context.Context, string) ([]byte, error) { return nil, os.ErrClosed })

	be := newFakeToolBackend()
	be.stdout["naabu"] = []byte("8.8.8.8:443\n8.8.8.8:80\n") // unsorted → CSV must sort

	cfg := portscanTestCfg()
	cfg.Web.Portscan.PassiveEnabled = false
	cfg.Web.Portscan.CDNCheck = false // no CDN filtering: ips_nocdn == seed
	cfg.Web.Portscan.Strategy = "naabu_nmap"
	app := newPortscanTestApp(t, be, cfg)
	writeSubdomainsIPs(t, app, "a.example.com - 8.8.8.8\n")

	res, err := (&WebPortscanTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Status != "done" {
		t.Fatalf("status = %v, want done", res.Status)
	}

	// hosts/naabu_open.txt written from the naabu stdout (backend has no -o file).
	naabuOpen, _ := os.ReadFile(filepath.Join(app.Target.WorkDir, "hosts", "naabu_open.txt"))
	if !strings.Contains(string(naabuOpen), "8.8.8.8:80") || !strings.Contains(string(naabuOpen), "8.8.8.8:443") {
		t.Errorf("naabu_open.txt missing open ports; got:\n%s", naabuOpen)
	}

	// naabu arg vector: -list <ips_nocdn> -silent -rate 1000 --top-ports 1000 -duc (T-13-03-02/03).
	nArgs, ok := be.argsFor("naabu")
	if !ok {
		t.Fatal("naabu was not invoked")
	}
	ipsNoCDN := filepath.Join(app.Target.WorkDir, ".tmp", "ips_nocdn.txt")
	if !hasSubsequence(nArgs, "-list", ipsNoCDN) {
		t.Errorf("naabu args missing -list <ips_nocdn>; got %v", nArgs)
	}
	if !containsToken(nArgs, "-silent") || !hasSubsequence(nArgs, "-rate", "1000") {
		t.Errorf("naabu args missing -silent / -rate 1000; got %v", nArgs)
	}
	// Ports MUST be split into separate argv tokens, never "--top-ports 1000" as one (T-13-03-02).
	if !hasSubsequence(nArgs, "--top-ports", "1000") {
		t.Errorf("naabu ports not split into argv tokens; got %v", nArgs)
	}
	if containsToken(nArgs, "--top-ports 1000") {
		t.Errorf("naabu ports passed as a single arg (T-13-03-02 violation); got %v", nArgs)
	}
	if !containsToken(nArgs, "-duc") {
		t.Errorf("naabu args missing -duc update-check guard (T-13-03-03); got %v", nArgs)
	}

	// nmap targeted: -p 80,443 -iL <ips_nocdn> (ports sorted CSV).
	mArgs, ok := be.argsFor("nmap")
	if !ok {
		t.Fatal("nmap was not invoked after naabu")
	}
	if !hasSubsequence(mArgs, "-p", "80,443") {
		t.Errorf("nmap args missing -p 80,443 (sorted CSV); got %v", mArgs)
	}
	if !hasSubsequence(mArgs, "-iL", ipsNoCDN) {
		t.Errorf("nmap args missing -iL <ips_nocdn>; got %v", mArgs)
	}
}

// -------------------------------------------------------------------------
// Degrade: naabu + nmap absent → StatusDone (not Errored); passive still runs
// -------------------------------------------------------------------------

func TestWebPortscanDegradesOnMissingTools(t *testing.T) {
	stubShodan(t, func(context.Context, string) ([]byte, error) { return nil, os.ErrDeadlineExceeded })

	be := newFakeToolBackend()
	be.errs["naabu"] = os.ErrNotExist // simulate absent / failing tool
	be.errs["nmap"] = os.ErrNotExist
	be.stdout["smap"] = []byte("passive-result\n")

	cfg := portscanTestCfg()
	cfg.Web.Portscan.CDNCheck = false
	cfg.Web.Portscan.Strategy = "naabu_nmap"
	app := newPortscanTestApp(t, be, cfg)
	writeSubdomainsIPs(t, app, "a.example.com - 8.8.8.8\n")

	res, err := (&WebPortscanTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("Run returned error on missing tools (must degrade): %v", err)
	}
	if res.Status == "errored" {
		t.Fatalf("status = errored; missing tools must degrade to done (D-O2)")
	}
	if res.Status != "done" {
		t.Fatalf("status = %v, want done", res.Status)
	}

	// Passive artefact still produced despite active tools failing.
	passive, _ := os.ReadFile(filepath.Join(app.Target.WorkDir, "hosts", "portscan_passive.txt"))
	if !strings.Contains(string(passive), "passive-result") {
		t.Errorf("passive artefact missing after active degrade; got:\n%s", passive)
	}
}

// -------------------------------------------------------------------------
// No IP seed → StatusSkipped
// -------------------------------------------------------------------------

func TestWebPortscanSkipsWithoutSeed(t *testing.T) {
	stubShodan(t, func(context.Context, string) ([]byte, error) { return nil, nil })
	be := newFakeToolBackend()
	cfg := portscanTestCfg()
	app := newPortscanTestApp(t, be, cfg) // no subdomains_ips.txt written

	res, err := (&WebPortscanTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Status != "skipped" {
		t.Errorf("status = %v, want skipped (no IP seed)", res.Status)
	}
}

// -------------------------------------------------------------------------
// nmapurls feedback: fixture nmap XML → web target URLs
// -------------------------------------------------------------------------

const fixtureNmapXML = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="8.8.8.8" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
      <port protocol="tcp" portid="443"><state state="open"/><service name="https" tunnel="ssl"/></port>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
      <port protocol="tcp" portid="8081"><state state="closed"/><service name="http"/></port>
    </ports>
  </host>
</nmaprun>`

func TestPortscanNmapXMLURLs(t *testing.T) {
	urls := portscanNmapXMLURLs([]byte(fixtureNmapXML))
	got := strings.Join(urls, ",")
	if !strings.Contains(got, "http://8.8.8.8:80") {
		t.Errorf("expected http://8.8.8.8:80 in %v", urls)
	}
	if !strings.Contains(got, "https://8.8.8.8:443") {
		t.Errorf("expected https://8.8.8.8:443 in %v", urls)
	}
	if strings.Contains(got, ":22") {
		t.Errorf("ssh port 22 should not yield a URL; got %v", urls)
	}
	if strings.Contains(got, ":8081") {
		t.Errorf("closed port 8081 should not yield a URL; got %v", urls)
	}
}

func TestWebPortscanNmapURLsFeedback(t *testing.T) {
	be := newFakeToolBackend()
	app := newPortscanTestApp(t, be, portscanTestCfg())
	hostsDir := filepath.Join(app.Target.WorkDir, "hosts")
	if err := os.MkdirAll(hostsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hostsDir, "portscan_active.xml"), []byte(fixtureNmapXML), 0o644); err != nil {
		t.Fatal(err)
	}

	portscanNmapURLsFeedback(app, hostsDir)

	webs, _ := os.ReadFile(filepath.Join(hostsDir, "webs.txt"))
	if !strings.Contains(string(webs), "http://8.8.8.8:80") {
		t.Errorf("hosts/webs.txt missing discovered URL; got:\n%s", webs)
	}
	// Fed back into the web target set.
	targetSet, _ := os.ReadFile(filepath.Join(app.Target.WorkDir, "webs", "webs.txt"))
	if !strings.Contains(string(targetSet), "https://8.8.8.8:443") {
		t.Errorf("webs/webs.txt missing discovered URL; got:\n%s", targetSet)
	}
}

// -------------------------------------------------------------------------
// Task 2: nerva service fingerprint
// -------------------------------------------------------------------------

// fixtureNervaJSONL is a stand-in for `nerva --json` output (one JSON obj/line).
const fixtureNervaJSONL = `{"host":"8.8.8.8","port":80,"protocol":"http"}
{"ip":"8.8.8.8","port":443,"service":"https"}`

func TestPortscanServiceFingerprintFromNaabu(t *testing.T) {
	be := newFakeToolBackend()
	be.stdout["nerva"] = []byte(fixtureNervaJSONL)
	app := newPortscanTestApp(t, be, portscanTestCfg())
	hostsDir := filepath.Join(app.Target.WorkDir, "hosts")
	if err := os.MkdirAll(hostsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// NF==2 numeric lines kept; the IPv6 (multi-colon) + no-colon lines dropped.
	if err := os.WriteFile(filepath.Join(hostsDir, "naabu_open.txt"),
		[]byte("8.8.8.8:80\n8.8.8.8:443\ngarbage-line\n2001:db8::1:22\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	ps := app.Cfg.Web.Portscan
	portscanServiceFingerprint(context.Background(), app, ps, hostsDir)

	// nerva arg vector: --json -l <targets> -w 2000 -o <service_fingerprints.jsonl>.
	nArgs, ok := be.argsFor("nerva")
	if !ok {
		t.Fatal("nerva was not invoked")
	}
	targetsFile := filepath.Join(app.Target.WorkDir, ".tmp", "service_fp_targets.txt")
	fpPath := filepath.Join(hostsDir, "service_fingerprints.jsonl")
	if !containsToken(nArgs, "--json") {
		t.Errorf("nerva args missing --json; got %v", nArgs)
	}
	if !hasSubsequence(nArgs, "-l", targetsFile) {
		t.Errorf("nerva args missing -l <targets>; got %v", nArgs)
	}
	if !hasSubsequence(nArgs, "-w", "2000") {
		t.Errorf("nerva args missing -w 2000 (TimeoutMS); got %v", nArgs)
	}
	if !hasSubsequence(nArgs, "-o", fpPath) {
		t.Errorf("nerva args missing -o <service_fingerprints.jsonl>; got %v", nArgs)
	}

	// Targets file built from naabu NF==2 lines.
	targets, _ := os.ReadFile(targetsFile)
	if !strings.Contains(string(targets), "8.8.8.8:80") || !strings.Contains(string(targets), "8.8.8.8:443") {
		t.Errorf("targets file missing naabu host:port; got:\n%s", targets)
	}
	if strings.Contains(string(targets), "garbage-line") {
		t.Errorf("non host:port line leaked into targets; got:\n%s", targets)
	}

	// service_fingerprints.jsonl (bash-contract) produced from nerva stdout.
	if data, _ := os.ReadFile(fpPath); !strings.Contains(string(data), "8.8.8.8") {
		t.Errorf("service_fingerprints.jsonl missing/empty; got:\n%s", data)
	}

	// Fingerprints reach the store via the hosts.nerva.jsonl staging file.
	staged, _ := os.ReadFile(filepath.Join(app.Target.WorkDir, "inputs", "hosts.nerva.jsonl"))
	if !strings.Contains(string(staged), "8.8.8.8") {
		t.Errorf("inputs/hosts.nerva.jsonl missing fingerprint records; got:\n%s", staged)
	}
	if !strings.Contains(string(staged), "http") {
		t.Errorf("inputs/hosts.nerva.jsonl missing service in tech; got:\n%s", staged)
	}
}

func TestPortscanServiceFingerprintGnmapFallback(t *testing.T) {
	be := newFakeToolBackend()
	be.stdout["nerva"] = []byte(fixtureNervaJSONL)
	app := newPortscanTestApp(t, be, portscanTestCfg())
	hostsDir := filepath.Join(app.Target.WorkDir, "hosts")
	if err := os.MkdirAll(hostsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// No naabu_open.txt → targets must come from the gnmap.
	gnmap := "Host: 1.2.3.4 ()\tPorts: 80/open/tcp//http///, 443/open/tcp//https///\tIgnored State: closed (0)\n"
	if err := os.WriteFile(filepath.Join(hostsDir, "portscan_active.gnmap"), []byte(gnmap), 0o644); err != nil {
		t.Fatal(err)
	}

	ps := app.Cfg.Web.Portscan
	portscanServiceFingerprint(context.Background(), app, ps, hostsDir)

	if _, ok := be.argsFor("nerva"); !ok {
		t.Fatal("nerva was not invoked from the gnmap fallback")
	}
	targets, _ := os.ReadFile(filepath.Join(app.Target.WorkDir, ".tmp", "service_fp_targets.txt"))
	if !strings.Contains(string(targets), "1.2.3.4:80") || !strings.Contains(string(targets), "1.2.3.4:443") {
		t.Errorf("gnmap-derived targets missing; got:\n%s", targets)
	}
}

func TestPortscanServiceFingerprintSkips(t *testing.T) {
	writeNaabu := func(app *appctx.AppContext) string {
		hostsDir := filepath.Join(app.Target.WorkDir, "hosts")
		_ = os.MkdirAll(hostsDir, 0o755)
		_ = os.WriteFile(filepath.Join(hostsDir, "naabu_open.txt"), []byte("8.8.8.8:80\n"), 0o644)
		return hostsDir
	}

	t.Run("disabled", func(t *testing.T) {
		be := newFakeToolBackend()
		cfg := portscanTestCfg()
		cfg.Web.Portscan.ServiceFingerprint.Enabled = false
		app := newPortscanTestApp(t, be, cfg)
		hostsDir := writeNaabu(app)
		portscanServiceFingerprint(context.Background(), app, cfg.Web.Portscan, hostsDir)
		if be.countCalls("nerva") != 0 {
			t.Error("nerva invoked despite ServiceFingerprint.Enabled=false")
		}
	})

	t.Run("wrong_engine", func(t *testing.T) {
		be := newFakeToolBackend()
		cfg := portscanTestCfg()
		cfg.Web.Portscan.ServiceFingerprint.Engine = "somethingelse"
		app := newPortscanTestApp(t, be, cfg)
		hostsDir := writeNaabu(app)
		portscanServiceFingerprint(context.Background(), app, cfg.Web.Portscan, hostsDir)
		if be.countCalls("nerva") != 0 {
			t.Error("nerva invoked despite Engine!=nerva")
		}
	})

	t.Run("nerva_absent", func(t *testing.T) {
		be := newFakeToolBackend()
		be.errs["nerva"] = os.ErrNotExist
		cfg := portscanTestCfg()
		app := newPortscanTestApp(t, be, cfg)
		hostsDir := writeNaabu(app)
		// Must not panic and must not write the staging record file.
		portscanServiceFingerprint(context.Background(), app, cfg.Web.Portscan, hostsDir)
		if _, err := os.Stat(filepath.Join(app.Target.WorkDir, "inputs", "hosts.nerva.jsonl")); err == nil {
			t.Error("fingerprint records written despite nerva being absent")
		}
	})
}

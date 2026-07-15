// ip_info_test.go — behavior tests for the IPInfoTask WHOISXML IP-target restore
// (13-05 Task 3).
//
// Proves the PAR-03 parity restore: for an IP-shaped target IPInfoTask makes the
// three WHOISXML GETs (reverse-ip / whois / geolocation) against an httptest
// server and writes the v1 trio osint/ip_<ip>_relations.txt / _whois.txt /
// _location.txt; the reverse-IP relation names become findings; the apiKey travels
// ONLY in the outbound URL (never argv — Tools is nil in the IP test) and is
// redacted from logs; an unset key skips cleanly; and the domain-target ASN/CIDR
// path is unregressed.
//
// Internal (package osint) to reach unexported helpers.
//
// Source: .planning/phases/13-domain-parity/13-05-PLAN.md Task 3.
package osint

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
	corelog "github.com/six2dez/reconftw/internal/core/log"
	"github.com/six2dez/reconftw/internal/core/task"
)

// fakeWhoisKey is a clearly-synthetic WHOISXML API key (non-AWS/private-key
// shaped) so redaction can be asserted without committing a real secret.
const fakeWhoisKey = "FAKE-WHOISXML-KEY-0123456789abcdefABCDEF"

// whoisXMLCapture records what the httptest WHOISXML server saw.
type whoisXMLCapture struct {
	mu      sync.Mutex
	apiKeys []string
	paths   []string
}

func (c *whoisXMLCapture) record(r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.apiKeys = append(c.apiKeys, r.URL.Query().Get("apiKey"))
	c.paths = append(c.paths, r.URL.Path)
}

func (c *whoisXMLCapture) sawKey(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, k := range c.apiKeys {
		if k == key {
			return true
		}
	}
	return false
}

func (c *whoisXMLCapture) hits() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.paths)
}

// newWhoisXMLServer serves the three WHOISXML endpoints under /reverse-ip,
// /whois, /geo (matching whoisXMLEndpointsFor's RECONFTW_WHOISXML_BASE_URL layout).
func newWhoisXMLServer(t *testing.T, cap *whoisXMLCapture) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/reverse-ip", func(w http.ResponseWriter, r *http.Request) {
		cap.record(r)
		_, _ = w.Write([]byte(`{"result":[{"name":"host-a.example.com"},{"name":"host-b.example.com"},{"name":"host-a.example.com"}]}`))
	})
	mux.HandleFunc("/whois", func(w http.ResponseWriter, r *http.Request) {
		cap.record(r)
		_, _ = w.Write([]byte(`{"WhoisRecord":{"domainName":"1.2.3.4","registrarName":"Example Registrar"}}`))
	})
	mux.HandleFunc("/geo", func(w http.ResponseWriter, r *http.Request) {
		cap.record(r)
		_, _ = w.Write([]byte(`{"ip":"1.2.3.4","location":{"country":"US","city":"Ashburn"}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// newIPInfoApp builds an AppContext with a redacting logger over buf. Tools is
// left nil for IP-target tests to PROVE no subprocess is used (a stray app.Tools
// call would panic).
func newIPInfoApp(t *testing.T, cfg *config.Config, domain string, isIP bool) (*appctx.AppContext, *bytes.Buffer) {
	t.Helper()
	buf := &bytes.Buffer{}
	logger := slog.New(corelog.NewRedactingHandler(
		slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}), &corelog.Redactor{}))
	app := &appctx.AppContext{
		Log:    logger,
		Cfg:    cfg,
		Target: &appctx.Target{Domain: domain, IsIP: isIP, WorkDir: t.TempDir()},
	}
	return app, buf
}

// TestIPInfoTask_WhoisXMLIPTarget is the happy path: an IP target with the key
// set → three WHOISXML files + reverse-IP findings; key only in the URL; redacted.
func TestIPInfoTask_WhoisXMLIPTarget(t *testing.T) {
	cap := &whoisXMLCapture{}
	srv := newWhoisXMLServer(t, cap)
	t.Setenv("RECONFTW_WHOISXML_BASE_URL", srv.URL)

	cfg := &config.Config{}
	cfg.OSINT.IPInfo.Enabled = true
	cfg.APIKeys.WhoisXML = corelog.Secret(fakeWhoisKey)

	app, buf := newIPInfoApp(t, cfg, "1.2.3.4", true)

	res, err := (&IPInfoTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Status != task.StatusDone {
		t.Fatalf("status = %q, want done (IP target must NOT be rejected)", res.Status)
	}

	osintDir := filepath.Join(app.Target.WorkDir, "osint")

	// 1. relations file: "<name> <ip>" per line, deduped.
	relData, err := os.ReadFile(filepath.Join(osintDir, "ip_1.2.3.4_relations.txt"))
	if err != nil {
		t.Fatalf("relations file not written: %v", err)
	}
	if !strings.Contains(string(relData), "host-a.example.com 1.2.3.4") {
		t.Errorf("relations.txt missing '<name> <ip>' line; got:\n%s", relData)
	}
	if n := strings.Count(string(relData), "host-a.example.com"); n != 1 {
		t.Errorf("relations.txt should dedup relation names (want 1, got %d)", n)
	}

	// 2. whois file (pretty JSON of the WHOISXML response).
	whoisData, err := os.ReadFile(filepath.Join(osintDir, "ip_1.2.3.4_whois.txt"))
	if err != nil {
		t.Fatalf("whois file not written: %v", err)
	}
	if !strings.Contains(string(whoisData), "Example Registrar") {
		t.Errorf("whois.txt missing whois content; got:\n%s", whoisData)
	}

	// 3. location file (ip + location).
	locData, err := os.ReadFile(filepath.Join(osintDir, "ip_1.2.3.4_location.txt"))
	if err != nil {
		t.Fatalf("location file not written: %v", err)
	}
	if !strings.Contains(string(locData), "Ashburn") {
		t.Errorf("location.txt missing geolocation content; got:\n%s", locData)
	}

	// 4. reverse-IP relations → findings.ip_info.jsonl.
	findings, err := os.ReadFile(filepath.Join(app.Target.WorkDir, "inputs", "findings.ip_info.jsonl"))
	if err != nil {
		t.Fatalf("findings.ip_info.jsonl not written: %v", err)
	}
	for _, want := range []string{`"category":"reverse-ip-relation"`, "host-a.example.com"} {
		if !strings.Contains(string(findings), want) {
			t.Errorf("findings.ip_info.jsonl missing %q; got:\n%s", want, findings)
		}
	}

	// 5. XCUT-07: the apiKey was sent in the outbound URL query (never argv — Tools is nil).
	if !cap.sawKey(fakeWhoisKey) {
		t.Errorf("apiKey %q never observed in an outbound WHOISXML query", fakeWhoisKey)
	}
	// 6. XCUT-07 L2: the key is registered → scrubbed from ALL log output.
	app.Log.Info("ip_info-test-probe", "key", fakeWhoisKey)
	if strings.Contains(buf.String(), fakeWhoisKey) {
		t.Fatalf("XCUT-07 VIOLATION: WHOISXML key leaked into log output:\n%s", buf.String())
	}
}

// TestIPInfoTask_WhoisXMLKeyUnsetSkips proves the key gate: no key → StatusSkipped,
// no requests, no files.
func TestIPInfoTask_WhoisXMLKeyUnsetSkips(t *testing.T) {
	cap := &whoisXMLCapture{}
	srv := newWhoisXMLServer(t, cap)
	t.Setenv("RECONFTW_WHOISXML_BASE_URL", srv.URL)

	cfg := &config.Config{}
	cfg.OSINT.IPInfo.Enabled = true
	// WhoisXML deliberately empty.

	app, _ := newIPInfoApp(t, cfg, "1.2.3.4", true)

	res, err := (&IPInfoTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Status != task.StatusSkipped {
		t.Errorf("status = %q, want skipped (WHOISXML key unset)", res.Status)
	}
	if cap.hits() != 0 {
		t.Errorf("key-unset made %d WHOISXML request(s); want 0", cap.hits())
	}
	if _, err := os.Stat(filepath.Join(app.Target.WorkDir, "osint", "ip_1.2.3.4_relations.txt")); err == nil {
		t.Error("relations file written despite unset key")
	}
}

// ipDomainBackend is a Backend double for the DOMAIN-target enrichment path:
// dnsx resolves an IP, mapcidr returns a CIDR (regression surface).
type ipDomainBackend struct {
	resolvedIP string
	cidr       string
}

func (b *ipDomainBackend) Exec(_ context.Context, tool *backend.Tool, _ []string) (*backend.Result, error) {
	switch tool.Name {
	case "dnsx":
		return &backend.Result{Stdout: []byte(b.resolvedIP + "\n"), ExitCode: 0}, nil
	case "mapcidr":
		return &backend.Result{Stdout: []byte(b.cidr + "\n"), ExitCode: 0}, nil
	}
	return &backend.Result{ExitCode: 0}, nil
}

func (b *ipDomainBackend) ExecEnv(ctx context.Context, tool *backend.Tool, args []string, _ []string) (*backend.Result, error) {
	return b.Exec(ctx, tool, args)
}

func (b *ipDomainBackend) Stream(_ context.Context, _ *backend.Tool, _ []string) (<-chan backend.Event, error) {
	ch := make(chan backend.Event)
	close(ch)
	return ch, nil
}

func (b *ipDomainBackend) StreamEnv(_ context.Context, _ *backend.Tool, _ []string, _ []string) (<-chan backend.Event, error) {
	ch := make(chan backend.Event)
	close(ch)
	return ch, nil
}

func (b *ipDomainBackend) HealthCheck(_ context.Context) error { return nil }
func (b *ipDomainBackend) Capacity() int                       { return 1 }

// TestIPInfoTask_DomainPathUnregressed proves the domain-target ASN/CIDR
// enrichment path still runs (an IP-shaped target takes the WHOISXML branch; a
// DOMAIN target must NOT). A CIDR finding is emitted for the resolved IP.
func TestIPInfoTask_DomainPathUnregressed(t *testing.T) {
	// Hermetic geo: point ipinfo.io at a local server returning empty JSON.
	geoSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(geoSrv.Close)
	t.Setenv("RECONFTW_IPINFO_BASE_URL", geoSrv.URL)

	cfg := &config.Config{}
	cfg.OSINT.IPInfo.Enabled = true
	cfg.OSINT.IPInfo.CIDREnabled = true
	cfg.OSINT.IPInfo.ASNEnabled = false

	app, _ := newIPInfoApp(t, cfg, "example.com", false) // NOT an IP
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "dnsx"})
	reg.Register(&backend.Tool{Name: "mapcidr"})
	app.Tools = backend.NewRunner(&ipDomainBackend{resolvedIP: "93.184.216.34", cidr: "93.184.216.0/24"}, reg, nil)

	res, err := (&IPInfoTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Status != task.StatusDone {
		t.Fatalf("status = %q, want done (domain path)", res.Status)
	}

	findings, err := os.ReadFile(filepath.Join(app.Target.WorkDir, "inputs", "findings.ip_info.jsonl"))
	if err != nil {
		t.Fatalf("findings.ip_info.jsonl not written (domain path regressed): %v", err)
	}
	for _, want := range []string{`"category":"cidr"`, "93.184.216.0/24"} {
		if !strings.Contains(string(findings), want) {
			t.Errorf("domain-path findings missing %q; got:\n%s", want, findings)
		}
	}
	// The WHOISXML IP-target files must NOT be produced for a domain target.
	if _, err := os.Stat(filepath.Join(app.Target.WorkDir, "osint", "ip_example.com_relations.txt")); err == nil {
		t.Error("WHOISXML relations file written for a DOMAIN target")
	}
}

func TestWhoisXMLFormatGeo(t *testing.T) {
	got := whoisXMLFormatGeo([]byte(`{"ip":"8.8.8.8","location":{"country":"US"}}`))
	if !strings.Contains(got, "8.8.8.8") || !strings.Contains(got, "US") {
		t.Errorf("whoisXMLFormatGeo = %q, want ip + location", got)
	}
	// Non-JSON falls back to the raw body.
	if got := whoisXMLFormatGeo([]byte("raw text")); got != "raw text" {
		t.Errorf("whoisXMLFormatGeo(raw) = %q, want passthrough", got)
	}
}

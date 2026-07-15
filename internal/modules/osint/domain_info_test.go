// domain_info_test.go — behavior tests for the DomainInfoTask Scopify fold
// (13-05 Task 2).
//
// Proves the PAR-03 parity restore: DomainInfoTask runs Scopify over the
// registrable company name (companyName / `unfurl format %r`) → osint/scopify.txt
// (single-writer), a Scopify failure degrades to StatusDone, and the existing
// whois + dnsx path is unchanged (regression guard).
//
// Internal (package osint) to reach unexported helpers + reuse the in-package
// AppContext idiom.
//
// Source: .planning/phases/13-domain-parity/13-05-PLAN.md Task 2.
package osint

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

// domainInfoBackend is a Backend double for the DomainInfoTask Run path. It
// dispatches on tool name: whois + dnsx return canned stdout (the regression
// surface), Scopify returns scopifyOut (or fails when scopifyFails). It records
// the Scopify args so the company-name derivation can be asserted.
type domainInfoBackend struct {
	whoisOut     string
	dnsxNSOut    string // returned for the dnsx -ns call
	scopifyOut   string
	scopifyFails bool
	scopifyArgs  []string // args captured from the most recent Scopify call
}

func (b *domainInfoBackend) Exec(_ context.Context, tool *backend.Tool, args []string) (*backend.Result, error) {
	switch tool.Name {
	case "whois":
		return &backend.Result{Stdout: []byte(b.whoisOut), ExitCode: 0}, nil
	case "dnsx":
		// Only answer the -ns lookup (regression: at least one dns record survives).
		for _, a := range args {
			if a == "-ns" {
				return &backend.Result{Stdout: []byte(b.dnsxNSOut), ExitCode: 0}, nil
			}
		}
		return &backend.Result{ExitCode: 0}, nil
	case "Scopify":
		b.scopifyArgs = append([]string(nil), args...)
		if b.scopifyFails {
			return nil, errors.New("Scopify: venv missing")
		}
		return &backend.Result{Stdout: []byte(b.scopifyOut), ExitCode: 0}, nil
	}
	return &backend.Result{ExitCode: 0}, nil
}

func (b *domainInfoBackend) ExecEnv(ctx context.Context, tool *backend.Tool, args []string, _ []string) (*backend.Result, error) {
	return b.Exec(ctx, tool, args)
}

func (b *domainInfoBackend) Stream(_ context.Context, _ *backend.Tool, _ []string) (<-chan backend.Event, error) {
	ch := make(chan backend.Event)
	close(ch)
	return ch, nil
}

func (b *domainInfoBackend) StreamEnv(_ context.Context, _ *backend.Tool, _ []string, _ []string) (<-chan backend.Event, error) {
	ch := make(chan backend.Event)
	close(ch)
	return ch, nil
}

func (b *domainInfoBackend) HealthCheck(_ context.Context) error { return nil }
func (b *domainInfoBackend) Capacity() int                       { return 1 }

// runDomainInfoTask wires a DomainInfoTask with the given backend and runs it.
func runDomainInfoTask(t *testing.T, be *domainInfoBackend) (*appctx.AppContext, task.Result) {
	t.Helper()
	workDir := t.TempDir()

	cfg := &config.Config{}
	cfg.OSINT.DomainInfo.Enabled = true

	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "whois"})
	reg.Register(&backend.Tool{Name: "dnsx"})
	reg.Register(&backend.Tool{Name: "Scopify"})
	runner := backend.NewRunner(be, reg, nil)

	app := &appctx.AppContext{
		Cfg:    cfg,
		Tools:  runner,
		Target: &appctx.Target{Domain: "example.com", WorkDir: workDir},
	}
	res, err := (&DomainInfoTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("DomainInfoTask.Run: unexpected error: %v", err)
	}
	return app, res
}

// TestDomainInfoTask_ScopifyWritesFile is the happy path: Scopify output →
// osint/scopify.txt with the company name derived correctly, while the whois +
// dnsx path is unchanged.
func TestDomainInfoTask_ScopifyWritesFile(t *testing.T) {
	be := &domainInfoBackend{
		whoisOut:   "Registrant Organization: ACME Inc\nRegistrar: Example Registrar\n",
		dnsxNSOut:  "ns1.example.com\n",
		scopifyOut: "AWS: 203.0.113.0/24\nCloudflare: 198.51.100.0/24\n",
	}
	app, res := runDomainInfoTask(t, be)

	if res.Status != task.StatusDone {
		t.Fatalf("status = %q, want done", res.Status)
	}

	// 1. Scopify → osint/scopify.txt (single-writer human file).
	scopifyData, err := os.ReadFile(filepath.Join(app.Target.WorkDir, "osint", "scopify.txt"))
	if err != nil {
		t.Fatalf("osint/scopify.txt not written: %v", err)
	}
	if !strings.Contains(string(scopifyData), "AWS: 203.0.113.0/24") {
		t.Errorf("scopify.txt missing scope content; got:\n%s", scopifyData)
	}

	// 2. company_name derived from the registrable name (example.com → "example").
	wantArgs := []string{"-c", "example"}
	if len(be.scopifyArgs) != 2 || be.scopifyArgs[0] != wantArgs[0] || be.scopifyArgs[1] != wantArgs[1] {
		t.Errorf("Scopify args = %v, want %v (registrable company name)", be.scopifyArgs, wantArgs)
	}

	// 3. Regression: whois → osint/domain_info_general.txt still written.
	whoisData, err := os.ReadFile(filepath.Join(app.Target.WorkDir, "osint", "domain_info_general.txt"))
	if err != nil {
		t.Fatalf("whois regression — domain_info_general.txt not written: %v", err)
	}
	if !strings.Contains(string(whoisData), "ACME Inc") {
		t.Errorf("domain_info_general.txt missing whois content; got:\n%s", whoisData)
	}

	// 4. Regression: whois + dns-ns records present in findings.domain_info.jsonl.
	findings, err := os.ReadFile(filepath.Join(app.Target.WorkDir, "inputs", "findings.domain_info.jsonl"))
	if err != nil {
		t.Fatalf("findings.domain_info.jsonl not written: %v", err)
	}
	for _, want := range []string{`"category":"whois"`, `"category":"dns-ns"`, "ns1.example.com"} {
		if !strings.Contains(string(findings), want) {
			t.Errorf("findings.domain_info.jsonl missing %q; got:\n%s", want, findings)
		}
	}
}

// TestDomainInfoTask_ScopifyDegrades proves a Scopify failure degrades to
// StatusDone with no scopify.txt, and the whois path is intact.
func TestDomainInfoTask_ScopifyDegrades(t *testing.T) {
	be := &domainInfoBackend{
		whoisOut:     "Registrant Organization: ACME Inc\n",
		dnsxNSOut:    "ns1.example.com\n",
		scopifyFails: true,
	}
	app, res := runDomainInfoTask(t, be)

	if res.Status != task.StatusDone {
		t.Errorf("status = %q, want done (best_effort degrade)", res.Status)
	}
	if _, err := os.Stat(filepath.Join(app.Target.WorkDir, "osint", "scopify.txt")); err == nil {
		t.Error("scopify.txt written despite Scopify failure")
	}
	// whois path unaffected.
	if _, err := os.Stat(filepath.Join(app.Target.WorkDir, "osint", "domain_info_general.txt")); err != nil {
		t.Errorf("whois regression on Scopify failure: %v", err)
	}
}

// TestDomainInfoTask_ScopifyEmptyOutputNoFile proves an empty Scopify report does
// not create an empty scopify.txt (best_effort — nothing to write).
func TestDomainInfoTask_ScopifyEmptyOutputNoFile(t *testing.T) {
	be := &domainInfoBackend{
		whoisOut:   "Registrant Organization: ACME Inc\n",
		scopifyOut: "   \n",
	}
	app, _ := runDomainInfoTask(t, be)
	if _, err := os.Stat(filepath.Join(app.Target.WorkDir, "osint", "scopify.txt")); err == nil {
		t.Error("scopify.txt written for empty Scopify output")
	}
}

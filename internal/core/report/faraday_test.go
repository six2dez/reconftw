package report_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/six2dez/reconftw/internal/core/report"
	sqlcgen "github.com/six2dez/reconftw/internal/store/sqlc"
)

func strptr(s string) *string { return &s }

// parsedFaraday mirrors the subset of the Faraday fplugin JSON export the tests
// assert on (the exported struct fields are unexported in the report package).
type parsedFaraday struct {
	Hosts []struct {
		IP              string   `json:"ip"`
		Hostnames       []string `json:"hostnames"`
		Vulnerabilities []struct {
			Name     string `json:"name"`
			Desc     string `json:"desc"`
			Severity string `json:"severity"`
			Status   string `json:"status"`
			Website  string `json:"website"`
		} `json:"vulnerabilities"`
	} `json:"hosts"`
}

// TestWriteFaraday_GroupsFindingsByHost exercises WriteFaraday (and through it
// buildFaradayExport) OFFLINE against a temp path — no network. It covers every
// grouping branch of buildFaradayExport:
//   - a host resolved with an IP (fh.IP = *IpCurrent)
//   - two findings sharing a MatchedAt (the grouped[key] reuse path)
//   - a finding whose host is absent entirely (fqdn IP fallback)
//   - a known host with a nil IpCurrent (also fqdn IP fallback)
func TestWriteFaraday_GroupsFindingsByHost(t *testing.T) {
	t.Parallel()
	hosts := []*sqlcgen.Host{
		{ID: 1, FQDN: "a.example.com", IpCurrent: strptr("10.0.0.1")},
		{ID: 2, FQDN: "c.example.com", IpCurrent: nil}, // host known, IP not resolved
	}
	findings := []*sqlcgen.Finding{
		{ID: 1, Title: "XSS", Description: "reflected", Severity: "high", MatchedAt: "a.example.com"},
		{ID: 2, Title: "Open redirect", Severity: "medium", MatchedAt: "a.example.com"}, // same host → group reuse
		{ID: 3, Title: "Info leak", Severity: "low", MatchedAt: "b.example.com"},        // no host row → fqdn fallback
		{ID: 4, Title: "Missing header", Severity: "info", MatchedAt: "c.example.com"},  // host known, nil IP → fqdn fallback
	}

	dest := filepath.Join(t.TempDir(), "faraday.json")
	if err := report.WriteFaraday(dest, findings, hosts); err != nil {
		t.Fatalf("WriteFaraday: %v", err)
	}

	raw, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	var export parsedFaraday
	if err := json.Unmarshal(raw, &export); err != nil {
		t.Fatalf("output not valid JSON: %v\nraw: %s", err, raw)
	}

	// Three host groups: a/b/c.example.com.
	if len(export.Hosts) != 3 {
		t.Fatalf("host groups = %d; want 3\nraw: %s", len(export.Hosts), raw)
	}

	// Index by the (single) hostname so map-iteration order does not matter.
	byHost := make(map[string]int, len(export.Hosts))
	for i, h := range export.Hosts {
		if len(h.Hostnames) != 1 {
			t.Fatalf("host %d hostnames = %v; want exactly one", i, h.Hostnames)
		}
		byHost[h.Hostnames[0]] = i
	}

	// a.example.com: IP resolved to 10.0.0.1, TWO grouped vulns.
	a, ok := byHost["a.example.com"]
	if !ok {
		t.Fatal("missing a.example.com host group")
	}
	if export.Hosts[a].IP != "10.0.0.1" {
		t.Errorf("a.example.com IP = %q; want 10.0.0.1 (resolved from host.IpCurrent)", export.Hosts[a].IP)
	}
	if len(export.Hosts[a].Vulnerabilities) != 2 {
		t.Errorf("a.example.com vulns = %d; want 2 (grouped)", len(export.Hosts[a].Vulnerabilities))
	}

	// b.example.com: no host row → IP falls back to the fqdn.
	b, ok := byHost["b.example.com"]
	if !ok {
		t.Fatal("missing b.example.com host group")
	}
	if export.Hosts[b].IP != "b.example.com" {
		t.Errorf("b.example.com IP = %q; want fqdn fallback b.example.com", export.Hosts[b].IP)
	}

	// c.example.com: known host but nil IpCurrent → fqdn fallback.
	c, ok := byHost["c.example.com"]
	if !ok {
		t.Fatal("missing c.example.com host group")
	}
	if export.Hosts[c].IP != "c.example.com" {
		t.Errorf("c.example.com IP = %q; want fqdn fallback c.example.com (nil IpCurrent)", export.Hosts[c].IP)
	}

	// Vuln fields are mapped through: status=open, website=MatchedAt, severity carried.
	v := export.Hosts[a].Vulnerabilities[0]
	if v.Status != "open" {
		t.Errorf("vuln status = %q; want open", v.Status)
	}
	if v.Website != "a.example.com" {
		t.Errorf("vuln website = %q; want a.example.com", v.Website)
	}
}

// TestWriteFaraday_EmptyInputs proves WriteFaraday writes a well-formed,
// empty-hosts export (no crash on nil findings/hosts) — the ADR §4.4
// error-isolation contract for empty artefacts.
func TestWriteFaraday_EmptyInputs(t *testing.T) {
	t.Parallel()
	dest := filepath.Join(t.TempDir(), "faraday-empty.json")
	if err := report.WriteFaraday(dest, nil, nil); err != nil {
		t.Fatalf("WriteFaraday(nil, nil): %v", err)
	}
	raw, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	var export parsedFaraday
	if err := json.Unmarshal(raw, &export); err != nil {
		t.Fatalf("output not valid JSON: %v\nraw: %s", err, raw)
	}
	if len(export.Hosts) != 0 {
		t.Errorf("empty export host groups = %d; want 0", len(export.Hosts))
	}
}

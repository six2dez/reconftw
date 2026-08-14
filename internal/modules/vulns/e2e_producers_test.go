// e2e_producers_test.go — locator contract for the real scanner parsers.
//
// e2e_findings_test.go proves the merge→gate→artefacts path works for a
// well-formed record. This file proves the records the PRODUCERS actually
// build are well-formed, by running the real parse functions over
// representative tool output and asserting every emitted record carries the
// locator the scope gate requires.
//
// This is the guard that was missing. The original bug was not a broken gate
// or a broken merge — both worked exactly as designed. It was that every
// VulnFindingRecord producer emitted records with no host and no url, and
// nothing anywhere asserted otherwise. Unit tests fed the gate hand-written
// JSON that already had a host, so they could never notice.
//
// Internal test package: the parsers are unexported on purpose.
package vulns

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/output"
)

// assertAllHaveLocator fails when any record would be rejected by the
// findings scope gate for lack of a host/url.
func assertAllHaveLocator(t *testing.T, producer string, recs []VulnFindingRecord) {
	t.Helper()
	if len(recs) == 0 {
		t.Fatalf("%s: parser produced no records — fixture no longer matches the "+
			"tool output format, so this contract is not actually being tested", producer)
	}
	for i, r := range recs {
		if r.Host == "" && r.URL == "" {
			t.Errorf("%s: record %d has neither host nor url — the findings scope "+
				"gate will reject it AND discard the whole merged batch with it "+
				"(%+v)", producer, i, r)
		}
	}
}

func TestE2EProducersEmitScopeLocator(t *testing.T) {
	t.Parallel()

	// nuclei's "host" is the full ORIGIN for HTTP templates, not a bare
	// hostname — the v1 fixture in tests/unit/test_new_tool_integrations.bats
	// records it as "host":"https://target.example.com". The earlier version of
	// these cases used a bare hostname, so they passed while every real DAST
	// finding was rejected by the scope gate for looking like a URL.
	t.Run("nuclei_dast origin-form host", func(t *testing.T) {
		out := []byte(`{"template-id":"xss-reflected","type":"http","info":{"severity":"high","tags":["xss"]},"host":"https://api.example.com","matched-at":"https://api.example.com/s?q=1"}` + "\n")
		recs := parseNucleiDAST(out)
		assertAllHaveLocator(t, "parseNucleiDAST", recs)
		if recs[0].Host != "api.example.com" {
			t.Errorf("Host = %q, want the bare hostname the scope gate matches", recs[0].Host)
		}
	})

	t.Run("nuclei_dast bare host", func(t *testing.T) {
		out := []byte(`{"template-id":"xss-reflected","type":"http","info":{"severity":"high","tags":["xss"]},"host":"api.example.com","matched-at":"https://api.example.com/s?q=1"}` + "\n")
		assertAllHaveLocator(t, "parseNucleiDAST", parseNucleiDAST(out))
	})

	t.Run("fuzzparams", func(t *testing.T) {
		out := []byte(`{"template-id":"sqli-error","type":"http","info":{"severity":"critical","tags":["sqli"]},"host":"https://shop.example.com:8443","matched-at":"https://shop.example.com:8443/p?id=1"}` + "\n")
		recs := parseFuzzparamsOutput(out)
		assertAllHaveLocator(t, "parseFuzzparamsOutput", recs)
		if recs[0].Host != "shop.example.com" {
			t.Errorf("Host = %q, want the bare hostname (scheme and port stripped)", recs[0].Host)
		}
	})

	t.Run("fray", func(t *testing.T) {
		out := []byte(`{"target":"https://waf.example.com/admin","bypassed":3,"total":10,"bypass_rate":0.3}` + "\n")
		recs, _ := parseFrayOutput(out, "xss")
		assertAllHaveLocator(t, "parseFrayOutput", recs)
	})

	t.Run("crlfuzz", func(t *testing.T) {
		out := []byte("https://api.example.com/redirect?url=%0d%0aSet-Cookie:x\n")
		assertAllHaveLocator(t, "parseCRLFuzzOutput", parseCRLFuzzOutput(out))
	})

	t.Run("bypass4xx", func(t *testing.T) {
		out := []byte("200 https://api.example.com/admin bypass\n")
		assertAllHaveLocator(t, "parseBypass4xxOutput", parseBypass4xxOutput(out))
	})

	t.Run("toxicache", func(t *testing.T) {
		out := []byte("https://cdn.example.com/asset.js\n")
		assertAllHaveLocator(t, "parseToxicacheOutput", parseToxicacheOutput(out))
	})

	t.Run("smuggling", func(t *testing.T) {
		out := []byte(`{"detected":true,"target":"https://edge.example.com/","method":"CL.TE"}` + "\n")
		var recs []VulnFindingRecord
		parseSmugglingOutput(out, &recs)
		assertAllHaveLocator(t, "parseSmugglingOutput", recs)
	})

	t.Run("brutespray", func(t *testing.T) {
		out := []byte("[+] ssh 10.0.0.5:22 - login successful - admin:hunter2\n")
		assertAllHaveLocator(t, "parseBrutesprayHits", parseBrutesprayHits(out))
	})
}

// TestE2EFindingHostNormalisation pins the locator normaliser used by producers
// that receive a raw scanner target: URL or bare host, with or without a port,
// and IPv6 literals that must not be mangled by naive port trimming.
func TestE2EFindingHostNormalisation(t *testing.T) {
	t.Parallel()
	cases := []struct{ in, want string }{
		{"https://API.Example.com/admin?q=1", "api.example.com"},
		{"http://api.example.com:8443/x", "api.example.com"},
		{"api.example.com", "api.example.com"},
		{"10.0.0.5:22", "10.0.0.5"},
		{"https://[2001:db8::1]:443/x", "2001:db8::1"},
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"[2001:db8::1]", "2001:db8::1"},
		{"API.EXAMPLE.COM", "api.example.com"},
		{"::1", "::1"},
		{"", ""},
	}
	for _, c := range cases {
		if got := findingHost(c.in); got != c.want {
			t.Errorf("findingHost(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestE2ESprayIPResolvesToInScopeHost covers the gap the second review found:
// the producer contract above only asserts a locator is present, so it passed
// while every credential-spray finding was being dropped downstream. brutespray
// targets come from the nmap gnmap and are IP literals, which a domain scope
// rejects — so the locator must be mapped back to the host that resolved to it.
func TestE2ESprayIPResolvesToInScopeHost(t *testing.T) {
	workDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(workDir, "artefacts"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The scan already discovered this pairing (web.httpx / subdomains geo).
	if err := os.WriteFile(filepath.Join(workDir, "artefacts", "hosts.jsonl"),
		[]byte(`{"host":"ssh.example.com","ip":"10.0.0.5"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	app := &appctx.AppContext{Target: &appctx.Target{WorkDir: workDir, Domain: "example.com"}}
	in := []VulnFindingRecord{{Host: "10.0.0.5", VulnClass: "credential-spray", Engine: "brutespray"}}

	got := sprayResolveScopeHosts(app, in)
	if got[0].Host != "ssh.example.com" {
		t.Errorf("Host = %q, want ssh.example.com — an IP locator is out of scope "+
			"under *.example.com and the finding would be dropped", got[0].Host)
	}

	// An unmappable IP keeps the IP: correct under an IP/CIDR target scope.
	unknown := sprayResolveScopeHosts(app,
		[]VulnFindingRecord{{Host: "192.0.2.9", VulnClass: "credential-spray"}})
	if unknown[0].Host != "192.0.2.9" {
		t.Errorf("unmappable IP must be left alone, got %q", unknown[0].Host)
	}
}

// TestE2EScannerFindingsSurviveRealScopeGate is the check the producer contract
// was missing: run records through the REAL merge + OutputTree, not just an
// emptiness assertion.
func TestE2EScannerFindingsSurviveRealScopeGate(t *testing.T) {
	workDir := t.TempDir()
	tree, err := output.NewTree(workDir, &output.DefaultScopeFilter{
		Patterns: []string{"example.com", "*.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(workDir, "artefacts"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "artefacts", "hosts.jsonl"),
		[]byte(`{"host":"ssh.example.com","ip":"10.0.0.5"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	app := &appctx.AppContext{Tree: tree, Target: &appctx.Target{WorkDir: workDir, Domain: "example.com"}}

	recs := sprayResolveScopeHosts(app, parseBrutesprayHits(
		[]byte("[+] ssh 10.0.0.5:22 - login successful - admin:hunter2\n")))

	var lines [][]byte
	for _, r := range recs {
		b, merr := json.Marshal(r)
		if merr != nil {
			t.Fatal(merr)
		}
		lines = append(lines, b)
	}
	if err := output.WriteJSONL(filepath.Join(workDir, "inputs", "findings.spray.jsonl"), lines); err != nil {
		t.Fatal(err)
	}
	if err := MergeVulnsFindings(context.Background(), app, "findings"); err != nil {
		t.Fatalf("merge: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(workDir, "artefacts", "findings.jsonl"))
	if err != nil {
		t.Fatalf("credential-spray finding never reached artefacts: %v", err)
	}
	if !bytes.Contains(body, []byte("credential-spray")) {
		t.Errorf("credential-spray missing: %s", body)
	}
}

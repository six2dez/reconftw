package resolvers_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/resolvers"
)

// ─────────────────────────────────────────────────────────────────────────────
// PATH CONTROL — why these two helpers exist.
//
// RunGenResolvers locates the tool with exec.LookPath("dnsvalidator") (gen.go:94),
// so every test in this file used to inherit the DEVELOPER'S PATH as a hidden
// input, and split into two bad halves depending on it:
//
//   - the fallback tests SKIPPED when dnsvalidator was present, so a properly
//     provisioned recon box tested LESS than a bare CI container;
//   - the two remaining tests ran the REAL tool with context.Background(), and
//     the real tool downloads and validates public resolver lists — gen.go:157
//     says so itself ("this one runs for minutes"). On 2026-09-02 that blew Go's
//     600s per-package timeout on reconbox3 and failed the whole
//     `go test -race ./...` guard, while the same commit passed in 1.4s on a
//     PATH that happened to exclude ~/.local/bin.
//
// A test whose result depends on which binaries the machine has is not a test.
// Both helpers make PATH an EXPLICIT input, so these tests are hermetic and
// finish in milliseconds on every machine.
// ─────────────────────────────────────────────────────────────────────────────

// withoutDnsvalidator points PATH at an empty directory, so exec.LookPath cannot
// find dnsvalidator (or anything else) and the HTTP fallback path is taken
// deterministically. t.Setenv restores the previous PATH when the test ends.
func withoutDnsvalidator(t *testing.T) {
	t.Helper()
	t.Setenv("PATH", t.TempDir())
	if _, err := exec.LookPath("dnsvalidator"); err == nil {
		t.Fatal("dnsvalidator still resolvable after emptying PATH — the fallback path would not be the one under test")
	}
}

// withFakeDnsvalidator puts a stub `dnsvalidator` on PATH that honours the real
// tool's -o contract (write the resolver list to the given path) and returns
// immediately. This lets the invocation test ASSERT that the tool was run and
// that its output was published, which the previous version never did — it
// called RunGenResolvers and logged any error, so it could not fail.
func withFakeDnsvalidator(t *testing.T, content string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake dnsvalidator uses a shell shebang; not applicable on Windows")
	}
	dir := t.TempDir()
	script := "#!/bin/sh\n" +
		"out=\"\"\n" +
		"while [ $# -gt 0 ]; do\n" +
		"  case \"$1\" in -o) out=\"$2\"; shift 2 ;; *) shift ;; esac\n" +
		"done\n" +
		"[ -n \"$out\" ] || exit 2\n" +
		"printf '%s' " + shellQuote(content) + " > \"$out\"\n"
	bin := filepath.Join(dir, "dnsvalidator")
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake dnsvalidator: %v", err)
	}
	t.Setenv("PATH", dir)
	if _, err := exec.LookPath("dnsvalidator"); err != nil {
		t.Fatalf("fake dnsvalidator not resolvable on PATH: %v", err)
	}
}

// shellQuote wraps s in single quotes for /bin/sh, escaping embedded quotes.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// makeTestConfig builds a *config.Config with resolver paths set to a temp dir.
func makeTestConfig(t *testing.T, resolversPath, trustedPath, downloadURL, trustedURL string) *config.Config {
	t.Helper()
	cfg := config.Defaults()
	cfg.Paths.Resolvers = resolversPath
	cfg.Paths.ResolversTrusted = trustedPath
	cfg.Paths.ResolversDownload.URL = downloadURL
	cfg.Paths.ResolversDownload.TrustedURL = trustedURL
	cfg.Advanced.Tools.DNSValidator.Threads = 2
	return cfg
}

// TestGenResolversCallsDnsvalidator verifies that when dnsvalidator is on PATH,
// RunGenResolvers RUNS it and PUBLISHES its output.
//
// The previous version skipped when the tool was absent and, when present, ran
// the real multi-minute network sweep and then merely logged any error — so it
// asserted nothing and could not fail. It now runs against a stub that honours
// the -o contract, which makes the invocation observable: if RunGenResolvers
// stopped calling dnsvalidator, or dropped its output, the content check below
// fails.
func TestGenResolversCallsDnsvalidator(t *testing.T) {
	const generated = "192.0.2.1\n192.0.2.2\n198.51.100.7\n"
	withFakeDnsvalidator(t, generated)

	tmp := t.TempDir()
	resolversPath := filepath.Join(tmp, "resolvers.txt")
	cfg := makeTestConfig(t, resolversPath, "", "", "")

	if err := resolvers.RunGenResolvers(context.Background(), cfg); err != nil {
		t.Fatalf("RunGenResolvers failed with dnsvalidator on PATH: %v", err)
	}

	data, err := os.ReadFile(resolversPath)
	if err != nil {
		t.Fatalf("resolver file not created: %v", err)
	}
	if !strings.Contains(string(data), "192.0.2.1") {
		t.Errorf("dnsvalidator output was not published to %s; got: %q\n"+
			"  The tool ran but its result did not reach the resolver list — the shape of the\n"+
			"  bug gen.go:157 stages against (a part-way sweep replacing a working list).",
			resolversPath, string(data))
	}
}

// TestGenResolversFallsBackToHTTP verifies that when dnsvalidator is NOT available
// and the fallback URL is provided (via httptest server), the resolver file is
// written with the server's response content.
func TestGenResolversFallsBackToHTTP(t *testing.T) {
	const resolverContent = "1.1.1.1\n8.8.8.8\n9.9.9.9\n"

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(resolverContent))
	}))
	defer srv.Close()
	resolvers.SetDownloadClientForTest(t, srv.Client())

	tmp := t.TempDir()
	resolversPath := filepath.Join(tmp, "resolvers.txt")

	cfg := makeTestConfig(t, resolversPath, "", srv.URL, "")
	// The fallback is only under test when the tool is genuinely absent. The
	// previous version said it "cannot prevent dnsvalidator from running" and
	// checked the output afterward, which meant that on a machine with the tool
	// this test silently exercised the generation path instead — and paid the
	// real sweep's runtime for it.
	withoutDnsvalidator(t)

	if err := resolvers.RunGenResolvers(context.Background(), cfg); err != nil {
		t.Fatalf("RunGenResolvers HTTP fallback failed: %v", err)
	}

	data, readErr := os.ReadFile(resolversPath)
	if readErr != nil {
		t.Fatalf("resolver file not created: %v", readErr)
	}
	if len(data) == 0 {
		t.Fatal("resolver file is empty after RunGenResolvers")
	}
}

// TestGenResolversFallsBackToHTTP_NoDnsvalidator explicitly tests the HTTP
// fallback path by using a config with no dnsvalidator-like binary available
// and verifying the file is populated from the test HTTP server.
func TestGenResolversFallsBackToHTTP_NoDnsvalidator(t *testing.T) {
	const resolverContent = "1.2.3.4\n5.6.7.8\n"

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(resolverContent))
	}))
	defer srv.Close()
	resolvers.SetDownloadClientForTest(t, srv.Client())

	tmp := t.TempDir()
	resolversPath := filepath.Join(tmp, "resolvers-fallback.txt")

	cfg := makeTestConfig(t, resolversPath, "", srv.URL, "")

	// Was: skip when dnsvalidator is on PATH. That inverted the coverage — the
	// better-provisioned the machine, the less this file tested.
	withoutDnsvalidator(t)

	if err := resolvers.RunGenResolvers(context.Background(), cfg); err != nil {
		t.Fatalf("RunGenResolvers returned error: %v", err)
	}

	data, readErr := os.ReadFile(resolversPath)
	if readErr != nil {
		t.Fatalf("resolver file not created: %v", readErr)
	}
	if !strings.Contains(string(data), "1.2.3.4") {
		t.Errorf("resolver file does not contain expected content; got: %q", string(data))
	}
}

// TestGenResolversOutputPathDefaultFallback verifies that when cfg.Paths.Resolvers
// is empty, RunGenResolvers uses a default path under ~/.config/reconftw/.
// We verify no panic and no error (fallback URL provided).
func TestGenResolversOutputPathDefaultFallback(t *testing.T) {
	const resolverContent = "10.0.0.1\n"

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(resolverContent))
	}))
	defer srv.Close()
	resolvers.SetDownloadClientForTest(t, srv.Client())

	// Build a config with empty Paths.Resolvers to trigger default path logic.
	cfg := config.Defaults()
	cfg.Paths.Resolvers = "" // trigger default path fallback
	cfg.Paths.ResolversDownload.URL = srv.URL

	// Override HOME to a temp dir so we do not pollute the real ~/.config/reconftw/.
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	// Was: skip when dnsvalidator is on PATH. Same inverted coverage as above.
	withoutDnsvalidator(t)

	if err := resolvers.RunGenResolvers(context.Background(), cfg); err != nil {
		t.Fatalf("RunGenResolvers with empty Paths.Resolvers returned error: %v", err)
	}
}

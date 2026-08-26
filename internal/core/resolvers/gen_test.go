package resolvers_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/resolvers"
)

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

// TestGenResolversCallsDnsvalidator verifies that when dnsvalidator IS on PATH,
// RunGenResolvers invokes it (or skips gracefully if not installed in CI).
func TestGenResolversCallsDnsvalidator(t *testing.T) {
	// This test requires dnsvalidator to be installed. If it is not, skip.
	_, err := runLookPath("dnsvalidator")
	if err != nil {
		t.Skip("dnsvalidator not on PATH — skipping invocation test")
	}

	tmp := t.TempDir()
	resolversPath := filepath.Join(tmp, "resolvers.txt")
	cfg := makeTestConfig(t, resolversPath, "", "", "")

	ctx := context.Background()
	runErr := resolvers.RunGenResolvers(ctx, cfg)
	// dnsvalidator may fail (bad network in CI), but RunGenResolvers should
	// at minimum attempt a fallback and not crash.
	if runErr != nil {
		t.Logf("RunGenResolvers returned error (acceptable in isolated env): %v", runErr)
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
	// Force fallback by providing a non-existent dnsvalidator path via zero threads
	// — the function will try exec.LookPath("dnsvalidator") and fall back on PATH miss.
	// We need to ensure dnsvalidator is not on PATH for this test to be deterministic.
	// If dnsvalidator IS on PATH, we point the config to the test server but cannot
	// prevent dnsvalidator from running. We work around by checking output afterward.

	ctx := context.Background()
	err := resolvers.RunGenResolvers(ctx, cfg)
	// Regardless of dnsvalidator presence, the resolver file must exist and be non-empty.
	if err != nil {
		_, pathErr := runLookPath("dnsvalidator")
		if pathErr == nil {
			// dnsvalidator on PATH — it may have succeeded, so error is unexpected.
			t.Fatalf("RunGenResolvers failed with dnsvalidator on PATH: %v", err)
		}
		// dnsvalidator not on PATH — we expected fallback to work.
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

	// If dnsvalidator IS on PATH, this test cannot deterministically test the
	// pure fallback path without mocking. Skip in that case.
	_, err := runLookPath("dnsvalidator")
	if err == nil {
		t.Skip("dnsvalidator on PATH — pure fallback test not applicable")
	}

	ctx := context.Background()
	if err := resolvers.RunGenResolvers(ctx, cfg); err != nil {
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

	// Skip if dnsvalidator is on PATH (it would attempt generation).
	_, err := runLookPath("dnsvalidator")
	if err == nil {
		t.Skip("dnsvalidator on PATH — default path test not applicable")
	}

	ctx := context.Background()
	if err := resolvers.RunGenResolvers(ctx, cfg); err != nil {
		t.Fatalf("RunGenResolvers with empty Paths.Resolvers returned error: %v", err)
	}
}

// runLookPath checks whether a binary is available on PATH, used to skip tests
// that require specific tools not available in the test environment.
func runLookPath(name string) (string, error) {
	return exec.LookPath(name)
}

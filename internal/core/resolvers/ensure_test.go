// ensure_test.go — coverage for boot-time resolver acquisition.
//
// Every case here is offline: the "download" mirror is an httptest server, so
// these assert the acquisition POLICY (freshness, opt-out, failure handling)
// rather than the reachability of a GitHub raw URL.

package resolvers_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/resolvers"
)

// newMirror serves a fixed resolver list and counts requests, so a test can
// assert that a fresh file was NOT re-downloaded.
func newMirror(t *testing.T, body string) (*httptest.Server, *int) {
	t.Helper()
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// baseCfg builds a config whose resolver paths live under dir and whose download
// URLs point at the local mirror.
func baseCfg(dir, url string) *config.Config {
	cfg := &config.Config{}
	cfg.Paths.Resolvers = filepath.Join(dir, "resolvers.txt")
	cfg.Paths.ResolversTrusted = filepath.Join(dir, "resolvers_trusted.txt")
	cfg.Paths.ResolversDownload.URL = url
	cfg.Paths.ResolversDownload.TrustedURL = url
	cfg.Cache.MaxAgeDaysResolvers = 7
	cfg.Subdomains.DNSResolve.UpdateResolvers = true
	return cfg
}

// TestEnsureDownloadsWhenAbsent is the blocker itself: a run on defaults, with
// nothing on disk, must end up with a usable list instead of an empty path.
func TestEnsureDownloadsWhenAbsent(t *testing.T) {
	dir := t.TempDir()
	srv, hits := newMirror(t, "1.1.1.1\n8.8.8.8\n")
	cfg := baseCfg(dir, srv.URL)

	st, err := resolvers.EnsureResolvers(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("EnsureResolvers: %v", err)
	}
	if !st.Usable {
		t.Fatal("status.Usable = false after a successful acquisition")
	}
	if !st.Refreshed {
		t.Error("status.Refreshed = false, want true — nothing was on disk")
	}
	if *hits == 0 {
		t.Error("no download was attempted for an absent resolver list")
	}
	data, readErr := os.ReadFile(cfg.Paths.Resolvers)
	if readErr != nil || !strings.Contains(string(data), "1.1.1.1") {
		t.Errorf("resolver file not written as expected: %v / %q", readErr, data)
	}
}

// TestEnsureSkipsWhenFresh pins the steady state: two os.Stat calls, no traffic.
// A boot-time hook that re-downloads on every scan would be its own defect.
func TestEnsureSkipsWhenFresh(t *testing.T) {
	dir := t.TempDir()
	srv, hits := newMirror(t, "1.1.1.1\n")
	cfg := baseCfg(dir, srv.URL)
	for _, p := range []string{cfg.Paths.Resolvers, cfg.Paths.ResolversTrusted} {
		if err := os.WriteFile(p, []byte("9.9.9.9\n"), 0o644); err != nil {
			t.Fatalf("seed %s: %v", p, err)
		}
	}

	st, err := resolvers.EnsureResolvers(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("EnsureResolvers: %v", err)
	}
	if !st.Usable || st.Refreshed {
		t.Errorf("usable=%v refreshed=%v — a fresh list must be left alone", st.Usable, st.Refreshed)
	}
	if *hits != 0 {
		t.Errorf("a fresh resolver list triggered %d download(s)", *hits)
	}
	// The seeded content must survive untouched.
	data, _ := os.ReadFile(cfg.Paths.Resolvers)
	if !strings.Contains(string(data), "9.9.9.9") {
		t.Errorf("fresh resolver file was overwritten: %q", data)
	}
}

// TestEnsureRefreshesWhenStale drives the cache.max_age_days_resolvers branch.
func TestEnsureRefreshesWhenStale(t *testing.T) {
	dir := t.TempDir()
	srv, hits := newMirror(t, "1.1.1.1\n")
	cfg := baseCfg(dir, srv.URL)
	if err := os.WriteFile(cfg.Paths.Resolvers, []byte("9.9.9.9\n"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	old := time.Now().Add(-30 * 24 * time.Hour)
	if err := os.Chtimes(cfg.Paths.Resolvers, old, old); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	if _, err := resolvers.EnsureResolvers(context.Background(), cfg, nil); err != nil {
		t.Fatalf("EnsureResolvers: %v", err)
	}
	if *hits == 0 {
		t.Error("a 30-day-old resolver list was not refreshed")
	}
}

// TestEnsureKeepsListWhenUpdateDisabled: update_resolvers=false opts out of
// REFRESHING a list, and must be honoured when one exists.
func TestEnsureKeepsListWhenUpdateDisabled(t *testing.T) {
	dir := t.TempDir()
	srv, hits := newMirror(t, "1.1.1.1\n")
	cfg := baseCfg(dir, srv.URL)
	cfg.Subdomains.DNSResolve.UpdateResolvers = false
	if err := os.WriteFile(cfg.Paths.Resolvers, []byte("9.9.9.9\n"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	old := time.Now().Add(-30 * 24 * time.Hour)
	if err := os.Chtimes(cfg.Paths.Resolvers, old, old); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	st, err := resolvers.EnsureResolvers(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("EnsureResolvers: %v", err)
	}
	if !st.Usable {
		t.Error("an existing list must stay usable when update_resolvers=false")
	}
	if *hits != 0 {
		t.Errorf("update_resolvers=false still triggered %d download(s)", *hits)
	}
}

// TestEnsureDownloadsDespiteUpdateDisabledWhenNothingOnDisk: the opt-out is not
// a licence to run with no list at all — that is the exact silent `-r ""` state
// this package exists to prevent.
func TestEnsureDownloadsDespiteUpdateDisabledWhenNothingOnDisk(t *testing.T) {
	dir := t.TempDir()
	srv, hits := newMirror(t, "1.1.1.1\n")
	cfg := baseCfg(dir, srv.URL)
	cfg.Subdomains.DNSResolve.UpdateResolvers = false

	st, err := resolvers.EnsureResolvers(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("EnsureResolvers: %v", err)
	}
	if !st.Usable || *hits == 0 {
		t.Errorf("usable=%v hits=%d — an absent list must be fetched even with update_resolvers=false",
			st.Usable, *hits)
	}
}

// TestEnsureErrorNamesTheRemedy: when acquisition fails and nothing is on disk,
// the operator must get a fix, not a bare transport error.
func TestEnsureErrorNamesTheRemedy(t *testing.T) {
	dir := t.TempDir()
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer dead.Close()
	cfg := baseCfg(dir, dead.URL)

	st, err := resolvers.EnsureResolvers(context.Background(), cfg, nil)
	if err == nil {
		t.Fatal("expected an error when the list could not be obtained")
	}
	if st.Usable {
		t.Error("status.Usable = true with no file on disk — the err/status contract is broken")
	}
	if !strings.Contains(err.Error(), "gen-resolvers") {
		t.Errorf("error offers no remedy: %v", err)
	}
}

// TestEnsureFailureIsNonFatalWithExistingList: a stale-but-present list beats
// aborting a scan over an unreachable mirror.
func TestEnsureFailureIsNonFatalWithExistingList(t *testing.T) {
	dir := t.TempDir()
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer dead.Close()
	cfg := baseCfg(dir, dead.URL)
	if err := os.WriteFile(cfg.Paths.Resolvers, []byte("9.9.9.9\n"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	old := time.Now().Add(-30 * 24 * time.Hour)
	if err := os.Chtimes(cfg.Paths.Resolvers, old, old); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	st, err := resolvers.EnsureResolvers(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("a failed refresh with a usable list on disk must not error: %v", err)
	}
	if !st.Usable {
		t.Error("status.Usable = false despite a readable list on disk")
	}
}

// TestEnsureEmptyPathIsActionable covers the state config.Load only reaches when
// neither XDG_CONFIG_HOME nor a home directory resolves.
func TestEnsureEmptyPathIsActionable(t *testing.T) {
	cfg := &config.Config{}
	_, err := resolvers.EnsureResolvers(context.Background(), cfg, nil)
	if err == nil {
		t.Fatal("an empty paths.resolvers must be an error, not a silent no-op")
	}
	if !strings.Contains(err.Error(), "paths.resolvers") {
		t.Errorf("error does not name the setting to fix: %v", err)
	}
}

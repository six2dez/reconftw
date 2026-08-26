// atomic_test.go — CR-06: a failed resolver download must not destroy the
// working list, a content-empty list must not count as usable, and the HTTPS
// control the package comments name must actually exist.
//
// Every server here is loopback-only (httptest). Nothing in this file contacts
// a host off the machine, and nothing resolves DNS — outbound UDP/53 is blocked
// on the box these were written on, so a test that needed it would be a test
// that never ran.

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

// goodList is what a working resolver list looks like on disk.
const goodList = "1.1.1.1\n8.8.8.8\n9.9.9.9\n8.8.4.4\n208.67.222.222\n"

// newTruncatingMirror serves a body that stops part-way: it announces a
// Content-Length far larger than what it writes, then aborts the connection.
// The client's io.Copy therefore fails with an unexpected EOF AFTER bytes have
// already been handed to it — which is exactly the shape that used to overwrite
// a good resolver list with a remnant.
func newTruncatingMirror(t *testing.T, partial string) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "1048576")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(partial))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		panic(http.ErrAbortHandler) // closes the connection mid-body, no test log noise
	}))
	t.Cleanup(srv.Close)
	resolvers.SetDownloadClientForTest(t, srv.Client())
	return srv
}

// staleCfg points a config at dir, seeds the main list with content, and ages it
// past the freshness window so EnsureResolvers actually attempts a download.
func staleCfg(t *testing.T, dir, url, seed string) *config.Config {
	t.Helper()
	cfg := &config.Config{}
	cfg.Paths.Resolvers = filepath.Join(dir, "resolvers.txt")
	cfg.Paths.ResolversTrusted = ""
	cfg.Paths.ResolversDownload.URL = url
	cfg.Cache.MaxAgeDaysResolvers = 7
	cfg.Subdomains.DNSResolve.UpdateResolvers = true
	if seed != "" {
		if err := os.WriteFile(cfg.Paths.Resolvers, []byte(seed), 0o644); err != nil {
			t.Fatalf("seed resolver list: %v", err)
		}
		old := time.Now().Add(-30 * 24 * time.Hour)
		if err := os.Chtimes(cfg.Paths.Resolvers, old, old); err != nil {
			t.Fatalf("age resolver list: %v", err)
		}
	}
	return cfg
}

// TestFailedDownloadLeavesExistingListByteIdentical is CR-06's primary claim.
// The assertion is byte identity, not "still non-empty": a partial list that is
// merely non-empty is precisely what used to pass every check downstream.
func TestFailedDownloadLeavesExistingListByteIdentical(t *testing.T) {
	dir := t.TempDir()
	srv := newTruncatingMirror(t, "1.2.3.4\n5.6.7.8\n")
	cfg := staleCfg(t, dir, srv.URL, goodList)

	before, err := os.ReadFile(cfg.Paths.Resolvers)
	if err != nil {
		t.Fatalf("read seed: %v", err)
	}

	_, _ = resolvers.EnsureResolvers(context.Background(), cfg, nil)

	after, err := os.ReadFile(cfg.Paths.Resolvers)
	if err != nil {
		t.Fatalf("resolver list gone after a failed download: %v", err)
	}
	if string(after) != string(before) {
		t.Fatalf("a failed download replaced the working resolver list\n"+
			"  before: %d bytes %q\n"+
			"  after:  %d bytes %q\n"+
			"the previous list must survive a mid-transfer failure entirely",
			len(before), string(before), len(after), string(after))
	}
}

// TestFailedDownloadWarningIsTrue: EnsureResolvers logs "continuing with the
// existing list" on a failed refresh. That sentence has to be true — the run
// continues either way, so a false one is worse than no message at all.
func TestFailedDownloadWarningIsTrue(t *testing.T) {
	dir := t.TempDir()
	srv := newTruncatingMirror(t, "1.2.3.4\n")
	cfg := staleCfg(t, dir, srv.URL, goodList)

	st, err := resolvers.EnsureResolvers(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("a failed refresh with a usable list on disk must not abort the run: %v", err)
	}
	if !st.Usable {
		t.Fatal("status.Usable = false — the existing list is readable and should keep the run going")
	}
	if st.Refreshed {
		t.Error("status.Refreshed = true after a failed download")
	}
	data, readErr := os.ReadFile(cfg.Paths.Resolvers)
	if readErr != nil || string(data) != goodList {
		t.Errorf("the list reported as kept is not the list on disk: %q (err %v)", string(data), readErr)
	}
}

// TestNonResolverContentIsNotUsable: a file can exist, be non-empty, and hold
// nothing a DNS resolver could ever be. Size is not usability — an HTML error
// page from a mirror that answered 200 is the case that reaches production.
func TestNonResolverContentIsNotUsable(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{"html error page", "<html><head><title>404 Not Found</title></head>\n<body>nope</body></html>\n"},
		{"git lfs pointer", "version https://git-lfs.github.com/spec/v1\noid sha256:deadbeef\nsize 12\n"},
		{"comments only", "# trickest resolvers\n# generated 2026-08-01\n\n"},
		{"whitespace only", "   \n\t\n \n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			cfg := &config.Config{}
			cfg.Paths.Resolvers = filepath.Join(dir, "resolvers.txt")
			cfg.Cache.MaxAgeDaysResolvers = 7
			if err := os.WriteFile(cfg.Paths.Resolvers, []byte(tc.content), 0o644); err != nil {
				t.Fatalf("seed: %v", err)
			}
			// A file that is not usable is also not fresh, so EnsureResolvers will
			// try to replace it. Point it at a closed loopback port so the attempt
			// fails locally: with no download URL set it would fall through to the
			// hardcoded GitHub mirror, and a unit test that quietly reaches the
			// internet is a unit test that passes for the wrong reason.
			cfg.Paths.ResolversDownload.URL = closedHTTPSURL(t)
			cfg.Subdomains.DNSResolve.UpdateResolvers = true

			st, err := resolvers.EnsureResolvers(context.Background(), cfg, nil)
			if st.Usable {
				t.Fatalf("a file holding %d bytes of %s was called usable — "+
					"every DNS operation downstream would then run on it", len(tc.content), tc.name)
			}
			if err == nil {
				t.Error("err == nil with an unusable list breaks the documented contract " +
					"(err == nil implies status.Usable)")
			}
		})
	}
}

// closedHTTPSURL returns an https:// loopback URL that nothing is listening on,
// so a download attempt fails at connect without leaving the machine.
func closedHTTPSURL(t *testing.T) string {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	resolvers.SetDownloadClientForTest(t, srv.Client())
	srv.Close()
	return url
}

// TestNonHTTPSDownloadURLIsRefused: gen.go's own comments claim "HTTPS enforced
// by hardcoded https:// scheme" and "URL from config (not user input); HTTPS
// enforced". The URL is config-controlled and, per WR-11, a reconftw.toml in the
// working directory reaches it. A named control that does not exist is worse
// than an absent one, so this asserts the refusal happens BEFORE any request.
func TestNonHTTPSDownloadURLIsRefused(t *testing.T) {
	hits := 0
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		_, _ = w.Write([]byte("6.6.6.6\n"))
	}))
	defer plain.Close()

	for _, url := range []string{plain.URL, "ftp://127.0.0.1/resolvers.txt", "127.0.0.1/resolvers.txt"} {
		dir := t.TempDir()
		cfg := staleCfg(t, dir, url, "")

		_, err := resolvers.EnsureResolvers(context.Background(), cfg, nil)
		if err == nil {
			t.Errorf("URL %q was accepted; a non-HTTPS resolver source must be refused", url)
			continue
		}
		if !strings.Contains(strings.ToLower(err.Error()), "https") {
			t.Errorf("URL %q refused, but the error does not say why: %v", url, err)
		}
	}
	if hits != 0 {
		t.Fatalf("the plain-HTTP mirror was contacted %d time(s) — the scheme check "+
			"must refuse before any request goes out", hits)
	}
}

// TestSuccessfulDownloadStillReplacesTheList guards the other direction: the
// atomicity fix must not turn acquisition into a no-op.
func TestSuccessfulDownloadStillReplacesTheList(t *testing.T) {
	const fresh = "203.0.113.1\n203.0.113.2\n"
	dir := t.TempDir()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(fresh))
	}))
	defer srv.Close()
	resolvers.SetDownloadClientForTest(t, srv.Client())

	cfg := staleCfg(t, dir, srv.URL, goodList)

	st, err := resolvers.EnsureResolvers(context.Background(), cfg, nil)
	if err != nil {
		t.Fatalf("EnsureResolvers: %v", err)
	}
	if !st.Usable || !st.Refreshed {
		t.Fatalf("status = %+v, want usable and refreshed", st)
	}
	data, readErr := os.ReadFile(cfg.Paths.Resolvers)
	if readErr != nil {
		t.Fatalf("read: %v", readErr)
	}
	if string(data) != fresh {
		t.Fatalf("list was not replaced by a successful download: %q", string(data))
	}
	// No debris beside the destination.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") || strings.Contains(e.Name(), "download") {
			t.Errorf("temp-file debris left beside the resolver list: %s", e.Name())
		}
	}
}

// TestFailedDownloadLeavesNoDebris: the temp file must be cleaned up on every
// error path. Inert, but a failure that litters beside the resolver list is
// still a failure the next reader has to reason about.
func TestFailedDownloadLeavesNoDebris(t *testing.T) {
	dir := t.TempDir()
	srv := newTruncatingMirror(t, "1.2.3.4\n")
	cfg := staleCfg(t, dir, srv.URL, goodList)

	_, _ = resolvers.EnsureResolvers(context.Background(), cfg, nil)

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if e.Name() != "resolvers.txt" {
			t.Errorf("unexpected file left behind after a failed download: %s", e.Name())
		}
	}
}

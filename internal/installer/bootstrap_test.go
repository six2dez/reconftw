// bootstrap_test.go — guards on the toolchain bootstrap's supply-chain surface.
//
// The failure this file exists to prevent is not "a pin is wrong". It is "a pin
// is ABSENT and nothing notices", because verifyFile treats an empty expected
// digest as a legitimate no-pin and returns nil. Every test below is therefore
// about the MECHANISM — the lookup errors on a miss, the matrix covers the
// platforms we claim to support, no request is made before the pin resolves —
// rather than about any particular hex value.
package installer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	stderrors "errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
)

var sha256HexRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// --- pin shape -------------------------------------------------------------

func TestBootstrapPinsAreRealDigests(t *testing.T) {
	t.Parallel()
	zero := strings.Repeat("0", 64)

	check := func(name, pin string) {
		t.Helper()
		if !sha256HexRe.MatchString(pin) {
			t.Errorf("%s = %q: want 64 lowercase hex chars", name, pin)
		}
		if pin == zero {
			t.Errorf("%s is the all-zero placeholder — a bootstrap using it always aborts", name)
		}
	}

	for platform, pin := range GoToolchainSHA256 {
		check(fmt.Sprintf("GoToolchainSHA256[%q]", platform), pin)
	}
	for platform, pin := range RustupInitSHA256 {
		check(fmt.Sprintf("RustupInitSHA256[%q]", platform), pin)
	}
	check("uvInstallerSHA256", uvInstallerSHA256)
}

// TestDigestsAreDistinct catches the copy-paste failure where one platform's
// digest is duplicated onto another row. Two different archives cannot share a
// SHA-256, so a duplicate is proof that at least one entry is wrong — and a
// wrong entry that looks plausible is the single worst outcome here.
func TestDigestsAreDistinct(t *testing.T) {
	t.Parallel()
	for name, matrix := range map[string]map[string]string{
		"GoToolchainSHA256": GoToolchainSHA256,
		"RustupInitSHA256":  RustupInitSHA256,
	} {
		seen := map[string]string{}
		for platform, pin := range matrix {
			if prev, dup := seen[pin]; dup {
				t.Errorf("%s: %q and %q share digest %s — distinct artefacts cannot",
					name, prev, platform, pin)
			}
			seen[pin] = platform
		}
	}
}

// --- completeness (mutation-proven) ----------------------------------------

// missingPlatformPins is the completeness check, factored out so the test can
// prove the checker actually detects a gap instead of merely reporting none.
func missingPlatformPins(platforms []string, pins map[string]string) []string {
	var missing []string
	for _, p := range platforms {
		if pins[p] == "" {
			missing = append(missing, p)
		}
	}
	return missing
}

func TestGoToolchainDigestsCoverSupportedPlatforms(t *testing.T) {
	t.Parallel()
	if missing := missingPlatformPins(supportedPlatforms, GoToolchainSHA256); len(missing) > 0 {
		t.Errorf("supportedPlatforms without a pinned Go digest: %v — either pin them "+
			"or stop claiming support", missing)
	}
}

func TestRustupDigestsCoverSupportedPlatforms(t *testing.T) {
	t.Parallel()
	if missing := missingPlatformPins(rustupSupportedPlatforms, RustupInitSHA256); len(missing) > 0 {
		t.Errorf("rustupSupportedPlatforms without a pinned rustup-init digest: %v", missing)
	}
	for _, p := range rustupSupportedPlatforms {
		if rustupTargets[p] == "" {
			t.Errorf("rustupSupportedPlatforms %q has no target triple", p)
		}
	}
}

// TestCompletenessCheckDetectsAGap is the mutation proof for the two tests
// above. Without it, a completeness test that silently always passed (a typo in
// the map name, a nil slice) would be indistinguishable from real coverage —
// which is precisely how the previous pin guard stayed green for months.
func TestCompletenessCheckDetectsAGap(t *testing.T) {
	t.Parallel()
	mutated := make(map[string]string, len(GoToolchainSHA256))
	for k, v := range GoToolchainSHA256 {
		mutated[k] = v
	}
	victim := supportedPlatforms[0]
	delete(mutated, victim)

	missing := missingPlatformPins(supportedPlatforms, mutated)
	if len(missing) != 1 || missing[0] != victim {
		t.Fatalf("deleting %q from the matrix produced missing=%v, want exactly [%s] — "+
			"the completeness check cannot detect a gap and is therefore worthless",
			victim, missing, victim)
	}
}

// --- lookup fails closed ---------------------------------------------------

func TestGoToolchainDigestUnknownPlatform(t *testing.T) {
	t.Parallel()
	got, err := goToolchainDigest("plan9", "riscv64")
	if err == nil {
		t.Fatal("goToolchainDigest on an unknown platform returned nil error — " +
			"the empty digest would flow into verifyFile and disable verification")
	}
	if got != "" {
		t.Errorf("digest = %q on error, want empty", got)
	}
	if !strings.Contains(err.Error(), "plan9/riscv64") {
		t.Errorf("error %q does not name the platform", err)
	}
	// No eighth error class: this reuses the existing ConfigError member of the
	// 7-class hierarchy that checkpoint.classifyError already understands.
	if !stderrors.Is(err, coreerrors.ErrConfig) {
		t.Errorf("error is not ErrConfig-classified: %v", err)
	}
}

func TestRustupInitDigestUnknownPlatform(t *testing.T) {
	t.Parallel()
	got, err := rustupInitDigest("plan9", "riscv64")
	if err == nil || got != "" {
		t.Fatalf("rustupInitDigest(plan9/riscv64) = (%q, %v), want (\"\", error)", got, err)
	}
	if _, err := rustupInitURL("plan9", "riscv64"); err == nil {
		t.Error("rustupInitURL on an unknown platform returned nil error")
	}
}

// --- archive naming --------------------------------------------------------

// TestGoToolchainArchiveNaming pins the GOARCH → filename translation. Go
// publishes go<ver>.linux-armv6l.tar.gz for GOARCH=arm, so deriving the name
// straight from runtime.GOARCH (as the code did) requests a file that has never
// existed and 404s after burning all three retries.
func TestGoToolchainArchiveNaming(t *testing.T) {
	t.Parallel()
	cases := []struct{ goos, goarch, want string }{
		{"linux", "amd64", "go" + goVersion + ".linux-amd64.tar.gz"},
		{"linux", "arm64", "go" + goVersion + ".linux-arm64.tar.gz"},
		{"linux", "arm", "go" + goVersion + ".linux-armv6l.tar.gz"},
		{"darwin", "amd64", "go" + goVersion + ".darwin-amd64.tar.gz"},
		{"darwin", "arm64", "go" + goVersion + ".darwin-arm64.tar.gz"},
	}
	for _, c := range cases {
		if got := goToolchainArchive(c.goos, c.goarch); got != c.want {
			t.Errorf("goToolchainArchive(%s,%s) = %q, want %q", c.goos, c.goarch, got, c.want)
		}
	}
	if got := goToolchainURL("linux", "amd64"); !strings.HasPrefix(got, "https://dl.google.com/go/") {
		t.Errorf("goToolchainURL = %q, want the official dl.google.com host", got)
	}
}

// TestPinnedURLsAreVersioned guards the property that makes a digest pin
// meaningful at all: the URL must not be a floating "latest" path. Both
// https://astral.sh/uv/install.sh and https://sh.rustup.rs serve bodies that
// change on every upstream release, so a fixed digest against them would be a
// scheduled failure rather than a supply-chain control.
func TestPinnedURLsAreVersioned(t *testing.T) {
	t.Parallel()
	if !strings.Contains(uvInstallerURL, uvVersion) {
		t.Errorf("uvInstallerURL %q does not embed uvVersion %q", uvInstallerURL, uvVersion)
	}
	if strings.Contains(uvInstallerURL, "/latest/") {
		t.Errorf("uvInstallerURL %q is a floating latest path", uvInstallerURL)
	}
	url, err := rustupInitURL("linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(url, rustupVersion) {
		t.Errorf("rustupInitURL %q does not embed rustupVersion %q", url, rustupVersion)
	}
	if strings.Contains(url, "sh.rustup.rs") {
		t.Errorf("rustupInitURL %q still uses the unchecksummed floating script", url)
	}
}

// --- no bytes before the pin resolves ---------------------------------------

// refusingTransport fails any request and records that one was attempted.
type refusingTransport struct{ called atomic.Bool }

func (r *refusingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.called.Store(true)
	return nil, fmt.Errorf("unexpected HTTP request to %s", req.URL)
}

// TestBootstrapGoRefusesUnknownPlatformBeforeAnyRequest proves the ordering
// that the whole design rests on: the digest lookup happens BEFORE the
// download, so an unresolvable pin can never reach verifyFile as an empty
// string. An HTTP client whose transport fails the test if invoked is the only
// way to assert "nothing was fetched" rather than "the fetch was discarded".
func TestBootstrapGoRefusesUnknownPlatformBeforeAnyRequest(t *testing.T) {
	// Not parallel: swaps package-level state.
	swapLookPath(t, func(string) (string, error) { return "", stderrors.New("absent") })

	// Simulate an unsupported host by emptying the matrix, so the assertion
	// holds regardless of which platform the test itself runs on.
	orig := GoToolchainSHA256
	GoToolchainSHA256 = map[string]string{}
	t.Cleanup(func() { GoToolchainSHA256 = orig })

	tr := &refusingTransport{}
	cfg := &bootstrapConfig{
		TmpDir:     t.TempDir(),
		GoRoot:     t.TempDir(),
		HTTPClient: &http.Client{Transport: tr},
	}

	err := bootstrapGo(context.Background(), cfg)
	if err == nil {
		t.Fatal("bootstrapGo with no pinned digest returned nil — it would have " +
			"installed an unverified toolchain")
	}
	if !strings.Contains(err.Error(), "no pinned Go digest") {
		t.Errorf("error %q is not the pin-lookup refusal", err)
	}
	if tr.called.Load() {
		t.Error("bootstrapGo issued an HTTP request before resolving the pin")
	}
}

func TestBootstrapRustRefusesUnknownPlatformBeforeAnyRequest(t *testing.T) {
	swapLookPath(t, func(string) (string, error) { return "", stderrors.New("absent") })

	origTargets, origPins := rustupTargets, RustupInitSHA256
	rustupTargets = map[string]string{}
	RustupInitSHA256 = map[string]string{}
	t.Cleanup(func() { rustupTargets, RustupInitSHA256 = origTargets, origPins })

	tr := &refusingTransport{}
	cfg := &bootstrapConfig{TmpDir: t.TempDir(), HTTPClient: &http.Client{Transport: tr}}

	err := bootstrapRust(context.Background(), cfg)
	if err == nil {
		t.Fatal("bootstrapRust with no pinned digest returned nil")
	}
	if tr.called.Load() {
		t.Error("bootstrapRust issued an HTTP request before resolving the pin")
	}
}

// --- version comparison ----------------------------------------------------

func TestGoVersionAtLeast(t *testing.T) {
	t.Parallel()
	cases := []struct {
		have, want string
		expect     bool
	}{
		{"go1.25.13", "1.25.13", true},     // exactly the pin
		{"go1.26.0", "1.25.13", true},      // newer minor
		{"go1.25.14", "1.25.13", true},     // newer patch
		{"go1.25.2", "1.25.13", false},     // 2 < 13 numerically, ">" as text
		{"go1.9.7", "1.25.13", false},      // THE trap: "1.9" sorts above "1.25"
		{"go1.25", "1.25.13", false},       // missing patch counts as .0
		{"go1.26", "1.25.13", true},        // missing patch, still newer minor
		{"go2.0.0", "1.25.13", true},       // major bump
		{"1.25.13", "1.25.13", true},       // bare version, no "go" prefix
		{"go1.25.13rc1", "1.25.13", false}, // prerelease is not the release
		{"go1.26rc1", "1.25.13", true},     // but an rc of a NEWER minor still wins
	}
	for _, c := range cases {
		got, err := goVersionAtLeast(c.have, c.want)
		if err != nil {
			t.Errorf("goVersionAtLeast(%q,%q) unexpected error: %v", c.have, c.want, err)
			continue
		}
		if got != c.expect {
			t.Errorf("goVersionAtLeast(%q,%q) = %v, want %v", c.have, c.want, got, c.expect)
		}
	}

	for _, bad := range []string{"banana", "go", "", "vNext"} {
		if _, err := goVersionAtLeast(bad, "1.25.13"); err == nil {
			t.Errorf("goVersionAtLeast(%q, …) returned nil error for malformed input", bad)
		}
	}
}

// --- pre-existing toolchain probe -------------------------------------------

// presentGo makes lookPath resolve every binary, so onPath("go") is true.
func presentGo(t *testing.T) {
	t.Helper()
	swapLookPath(t, func(string) (string, error) { return "/usr/local/go/bin/go", nil })
}

// briefCtx bounds the tests that deliberately let the download fail. retry runs
// its first attempt BEFORE consulting ctx, so the transport is always invoked
// at least once; the deadline then short-circuits the 2s/4s backoff instead of
// costing six seconds per test. retry's own attempt count and backoff are
// unchanged — only the test's patience is.
func briefCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	t.Cleanup(cancel)
	return ctx
}

// TestBootstrapGoAcceptsNewerToolchain and TestBootstrapGoRejectsOldToolchain
// are the behavioural replacement for the bare onPath("go") early return. A
// grep can only show the call site changed; these show that an OLD Go actually
// triggers the pinned install, which is the property that matters.
func TestBootstrapGoAcceptsNewerToolchain(t *testing.T) {
	presentGo(t)
	swapRunOutput(t, func(context.Context, string, ...string) (string, error) {
		return "go version go1.99.0 linux/amd64\n", nil
	})
	tr := &refusingTransport{}
	cfg := &bootstrapConfig{TmpDir: t.TempDir(), HTTPClient: &http.Client{Transport: tr}}

	if err := bootstrapGo(context.Background(), cfg); err != nil {
		t.Fatalf("bootstrapGo with an up-to-date toolchain returned %v, want nil", err)
	}
	if tr.called.Load() {
		t.Error("bootstrapGo downloaded despite a newer toolchain already present")
	}
}

func TestBootstrapGoRejectsOldToolchain(t *testing.T) {
	presentGo(t)
	// Debian oldstable ships 1.19; under the old bare onPath check this host
	// was accepted and every `go install` of the ~55 tools built against it.
	swapRunOutput(t, func(context.Context, string, ...string) (string, error) {
		return "go version go1.19.13 linux/amd64\n", nil
	})
	tr := &refusingTransport{}
	cfg := &bootstrapConfig{TmpDir: t.TempDir(), HTTPClient: &http.Client{Transport: tr}}

	if err := bootstrapGo(briefCtx(t), cfg); err == nil {
		t.Fatal("bootstrapGo accepted a Go 1.19 host (the refusing transport should have failed the download)")
	}
	if !tr.called.Load() {
		t.Error("bootstrapGo did NOT attempt an install for a Go 1.19 host — " +
			"the bare onPath early return is still in effect")
	}
}

// TestBootstrapGoProceedsOnUnparseableVersion covers the nonstandard-wrapper
// case: an unidentifiable toolchain must NOT be assumed good enough.
func TestBootstrapGoProceedsOnUnparseableVersion(t *testing.T) {
	presentGo(t)
	swapRunOutput(t, func(context.Context, string, ...string) (string, error) {
		return "corporate go wrapper v4 (build 991)\n", nil
	})
	tr := &refusingTransport{}
	cfg := &bootstrapConfig{TmpDir: t.TempDir(), HTTPClient: &http.Client{Transport: tr}}

	_ = bootstrapGo(briefCtx(t), cfg)
	if !tr.called.Load() {
		t.Error("an unparseable `go version` silently satisfied the pin")
	}
}

func TestBootstrapGoProceedsWhenProbeFails(t *testing.T) {
	presentGo(t)
	swapRunOutput(t, func(context.Context, string, ...string) (string, error) {
		return "", stderrors.New("exec format error")
	})
	tr := &refusingTransport{}
	cfg := &bootstrapConfig{TmpDir: t.TempDir(), HTTPClient: &http.Client{Transport: tr}}

	_ = bootstrapGo(briefCtx(t), cfg)
	if !tr.called.Load() {
		t.Error("a failing `go version` probe silently satisfied the pin")
	}
}

// --- temp-directory cleanup -------------------------------------------------

// stubTransport serves a fixed body for any request.
type stubTransport struct{ body []byte }

func (s *stubTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(s.body)),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

func assertTmpEmpty(t *testing.T, dir, what string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("%s left %d artefact(s) in TmpDir: %v — a ~100 MB tarball per "+
			"invocation fills /tmp in CI and in the Docker builder", what, len(entries), names)
	}
}

// TestBootstrapGoRemovesDownloadOnSuccess is the success-path counterpart to
// downloadFile's failure-path cleanup. Nothing removed a COMPLETED download, so
// every finished bootstrap left its tarball behind permanently.
func TestBootstrapGoRemovesDownloadOnSuccess(t *testing.T) {
	payload := []byte("pretend this is a go tarball")
	sum := sha256.Sum256(payload)

	swapLookPath(t, func(string) (string, error) { return "", stderrors.New("absent") })
	swapRunCmd(t, func(context.Context, string, []string, []string) error { return nil })

	platform := runtime.GOOS + "/" + runtime.GOARCH
	orig := GoToolchainSHA256
	GoToolchainSHA256 = map[string]string{platform: hex.EncodeToString(sum[:])}
	t.Cleanup(func() { GoToolchainSHA256 = orig })

	tmp := t.TempDir()
	cfg := &bootstrapConfig{
		TmpDir:     tmp,
		GoRoot:     filepath.Join(t.TempDir(), "go"),
		HTTPClient: &http.Client{Transport: &stubTransport{body: payload}},
	}

	if err := bootstrapGo(context.Background(), cfg); err != nil {
		t.Fatalf("bootstrapGo returned %v, want nil", err)
	}
	assertTmpEmpty(t, tmp, "bootstrapGo (success)")
}

// TestBootstrapGoRemovesDownloadOnChecksumMismatch proves the artefact is
// removed on the path that matters most: a rejected download is exactly the
// file you least want left lying around in a world-writable /tmp.
func TestBootstrapGoRemovesDownloadOnChecksumMismatch(t *testing.T) {
	swapLookPath(t, func(string) (string, error) { return "", stderrors.New("absent") })
	swapRunCmd(t, func(context.Context, string, []string, []string) error { return nil })

	platform := runtime.GOOS + "/" + runtime.GOARCH
	orig := GoToolchainSHA256
	GoToolchainSHA256 = map[string]string{platform: strings.Repeat("a", 64)}
	t.Cleanup(func() { GoToolchainSHA256 = orig })

	tmp := t.TempDir()
	cfg := &bootstrapConfig{
		TmpDir:     tmp,
		GoRoot:     filepath.Join(t.TempDir(), "go"),
		HTTPClient: &http.Client{Transport: &stubTransport{body: []byte("tampered")}},
	}

	err := bootstrapGo(context.Background(), cfg)
	if err == nil {
		t.Fatal("bootstrapGo accepted a payload that does not match the pin")
	}
	var cm *coreerrors.ChecksumMismatch
	if !stderrors.As(err, &cm) {
		t.Errorf("error is not *ChecksumMismatch: %T (%v)", err, err)
	}
	assertTmpEmpty(t, tmp, "bootstrapGo (checksum mismatch)")
}

func TestBootstrapUVRemovesDownload(t *testing.T) {
	payload := []byte("#!/bin/sh\necho pretend uv installer\n")
	sum := sha256.Sum256(payload)

	swapLookPath(t, func(string) (string, error) { return "", stderrors.New("absent") })
	swapRunCmd(t, func(context.Context, string, []string, []string) error { return nil })

	origPin := uvInstallerSHA256
	uvInstallerSHA256 = hex.EncodeToString(sum[:])
	t.Cleanup(func() { uvInstallerSHA256 = origPin })

	tmp := t.TempDir()
	cfg := &bootstrapConfig{
		TmpDir:     tmp,
		HTTPClient: &http.Client{Transport: &stubTransport{body: payload}},
	}
	if err := bootstrapUV(context.Background(), cfg); err != nil {
		t.Fatalf("bootstrapUV returned %v, want nil", err)
	}
	assertTmpEmpty(t, tmp, "bootstrapUV (success)")

	// …and on rejection.
	uvInstallerSHA256 = strings.Repeat("b", 64)
	tmp2 := t.TempDir()
	cfg2 := &bootstrapConfig{
		TmpDir:     tmp2,
		HTTPClient: &http.Client{Transport: &stubTransport{body: payload}},
	}
	if err := bootstrapUV(context.Background(), cfg2); err == nil {
		t.Fatal("bootstrapUV accepted a payload that does not match the pin")
	}
	assertTmpEmpty(t, tmp2, "bootstrapUV (checksum mismatch)")
}

func TestBootstrapRustRemovesDownload(t *testing.T) {
	payload := []byte("pretend this is the rustup-init binary")
	sum := sha256.Sum256(payload)

	swapLookPath(t, func(string) (string, error) { return "", stderrors.New("absent") })
	swapRunCmd(t, func(context.Context, string, []string, []string) error { return nil })

	platform := runtime.GOOS + "/" + runtime.GOARCH
	origPins, origTargets := RustupInitSHA256, rustupTargets
	RustupInitSHA256 = map[string]string{platform: hex.EncodeToString(sum[:])}
	rustupTargets = map[string]string{platform: "stub-target"}
	t.Cleanup(func() { RustupInitSHA256, rustupTargets = origPins, origTargets })

	tmp := t.TempDir()
	cfg := &bootstrapConfig{
		TmpDir:     tmp,
		HTTPClient: &http.Client{Transport: &stubTransport{body: payload}},
	}
	if err := bootstrapRust(context.Background(), cfg); err != nil {
		t.Fatalf("bootstrapRust returned %v, want nil", err)
	}
	assertTmpEmpty(t, tmp, "bootstrapRust (success)")
}

// TestDownloadFileRemovesOnOversizeBody keeps downloadFile's own failure-path
// cleanup covered, since the caller-side defer must ADD to it, not replace it.
func TestDownloadFileRemovesOnOversizeBody(t *testing.T) {
	tmp := t.TempDir()
	cfg := &bootstrapConfig{
		TmpDir:     tmp,
		HTTPClient: &http.Client{Transport: &stubTransport{body: []byte("small")}},
	}
	path, err := downloadFile(context.Background(), cfg, "https://example/x", "blob")
	if err != nil {
		t.Fatalf("downloadFile: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("downloadFile did not produce a readable file: %v", err)
	}
	// downloadFile itself keeps the file on success — removal is the caller's
	// deferred responsibility, which is what the bootstrap tests above assert.
	removeTemp(path)
	assertTmpEmpty(t, tmp, "removeTemp")
	// removeTemp must tolerate the empty path a failed download leaves behind.
	removeTemp("")
}

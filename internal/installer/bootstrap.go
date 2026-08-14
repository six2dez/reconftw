package installer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
)

// --- Bootstrapper SHA-256 pins (INST-03 / INST-09 / XCUT-08) ---
//
// The pins, the versions they describe, and their provenance now live in
// checksums.go. They used to be three 64-zero sentinels here. Those were
// honest about being fail-closed, but the practical effect was that a real
// clean-machine bootstrap ALWAYS aborted, while the test suite only asserted
// the sentinels were non-empty hex — so CI stayed green over a feature that
// could not work. See checksums.go for the vendor sources of every digest.

// bootstrapConfig carries the few knobs the bootstrappers need; kept as a struct
// so callers (and tests) can redirect downloads to a temp dir.
type bootstrapConfig struct {
	TmpDir     string // download scratch dir; "" → os.TempDir()
	GoRoot     string // install prefix for Go; "" → /usr/local/go
	HTTPClient *http.Client
}

func (c *bootstrapConfig) tmp() string {
	if c.TmpDir != "" {
		return c.TmpDir
	}
	return os.TempDir()
}

// bootstrapDownloadTimeout bounds a single toolchain download end to end. The
// default client has NO timeout, so a server that accepts the connection and
// then stalls hangs `reconftw install` forever with no output — on a clean
// machine that is the very first thing a new user runs.
const bootstrapDownloadTimeout = 15 * time.Minute

// maxBootstrapDownloadBytes caps a single download. The Go tarball is the
// largest legitimate artefact at roughly 250 MB, so 1 GiB is generous while
// still bounding a misbehaving or hostile server that would otherwise stream
// until the disk fills.
const maxBootstrapDownloadBytes = 1 << 30

func (c *bootstrapConfig) client() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: bootstrapDownloadTimeout}
}

// verifyFile compares the SHA-256 of the file at path against expectedSHA256.
//
// Integrity model (D-01): go/python/system tool kinds rely on go.sum / PyPI for
// integrity, so an empty expectedSHA256 is a legitimate "no explicit pin"
// (returns nil). Bootstrappers and go_clone binaries MUST pass a non-empty pin.
//
// That empty-string fast path is why the bootstrappers resolve their digests
// through goToolchainDigest / rustupInitDigest, which return an ERROR on a
// lookup miss rather than the zero value: passing "" here would not "fail to
// find a pin", it would silently switch verification OFF for that platform
// while every log line still said the download was verified (BLOCKER 1).
func verifyFile(_ context.Context, path, expectedSHA256, sourceURL string) error {
	if expectedSHA256 == "" {
		return nil // no explicit pin (go.sum / PyPI integrity, Pattern 7)
	}
	f, err := os.Open(path) //nolint:gosec // path is installer-controlled temp file, not user input
	if err != nil {
		return fmt.Errorf("verify %s: %w", path, err)
	}
	defer f.Close() //nolint:errcheck // read-only hash path
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("verify %s: %w", path, err)
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != expectedSHA256 {
		return &coreerrors.ChecksumMismatch{URL: sourceURL, Expected: expectedSHA256, Got: got}
	}
	return nil
}

// retry runs fn up to attempts times with linear back-off (baseDelay * attempt),
// honoring ctx cancellation between attempts. Returns the last error on failure.
func retry(ctx context.Context, attempts int, baseDelay time.Duration, fn func() error) error {
	if attempts < 1 {
		attempts = 1
	}
	var last error
	for i := 1; i <= attempts; i++ {
		if err := fn(); err == nil {
			return nil
		} else {
			last = err
		}
		if i == attempts {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(baseDelay * time.Duration(i)):
		}
	}
	return last
}

// downloadFile fetches url into a private temp file under cfg.tmp() and
// returns its path.
//
// The destination is created with os.CreateTemp rather than a fixed
// filepath.Join(tmp, name): a predictable path in a world-writable /tmp lets a
// local attacker pre-create or symlink the target and have the installer write
// a toolchain archive through it — and this code runs as root on a clean
// machine. CreateTemp uses an unpredictable suffix, O_EXCL and mode 0600.
//
// The body is read through an io.LimitReader so a server streaming without end
// cannot fill the disk, and the transfer is bounded by the client timeout.
func downloadFile(ctx context.Context, cfg *bootstrapConfig, url, name string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := cfg.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("download %s: %w", url, err)
	}
	defer resp.Body.Close() //nolint:errcheck // response drain
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}

	out, err := os.CreateTemp(cfg.tmp(), name+"-*")
	if err != nil {
		return "", fmt.Errorf("download %s: create temp file: %w", url, err)
	}
	dst := out.Name()

	// LimitReader n+1 so hitting exactly the cap is distinguishable from a
	// file that legitimately ends at the limit.
	written, err := io.Copy(out, io.LimitReader(resp.Body, maxBootstrapDownloadBytes+1))
	if err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return "", err
	}
	if written > maxBootstrapDownloadBytes {
		_ = out.Close()
		_ = os.Remove(dst)
		return "", fmt.Errorf("download %s: exceeded %d byte limit — refusing to continue",
			url, int64(maxBootstrapDownloadBytes))
	}
	// Close explicitly rather than by defer: this is a WRITE path, so Close is where a
	// buffered-flush or disk-full failure surfaces. Ignoring it would hand the caller a
	// path to a TRUNCATED toolchain archive and report the download as successful.
	if err := out.Close(); err != nil {
		return "", fmt.Errorf("download %s: close %s: %w", url, dst, err)
	}
	return dst, nil
}

// bootstrapGo installs the pinned Go toolchain to cfg.GoRoot when `go` is absent
// (D-02). It downloads the official tarball, verifies it against the
// per-platform pin from checksums.go, and extracts via tar.
// Mirrors install.sh:install_golang_version().
func bootstrapGo(ctx context.Context, cfg *bootstrapConfig) error {
	if onPath("go") {
		return nil // already present (idempotent)
	}
	goRoot := cfg.GoRoot
	if goRoot == "" {
		goRoot = "/usr/local/go"
	}
	// Resolve the pin FIRST. An unsupported platform must cost zero bandwidth
	// and, more importantly, must never reach verifyFile with an empty digest.
	want, err := goToolchainDigest(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return fmt.Errorf("bootstrap go: %w", err)
	}
	tarball := goToolchainArchive(runtime.GOOS, runtime.GOARCH)
	url := goToolchainURL(runtime.GOOS, runtime.GOARCH)
	var path string
	if err := retry(ctx, 3, 2*time.Second, func() error {
		p, err := downloadFile(ctx, cfg, url, tarball)
		path = p
		return err
	}); err != nil {
		return fmt.Errorf("bootstrap go: %w", err)
	}
	if err := verifyFile(ctx, path, want, url); err != nil {
		return fmt.Errorf("bootstrap go: %w", err)
	}
	if err := os.RemoveAll(goRoot); err != nil {
		return fmt.Errorf("bootstrap go: clear %s: %w", goRoot, err)
	}
	// tar -C <parent> -xzf <tarball> extracts a top-level `go/` dir.
	return runCmd(ctx, "tar", []string{"-C", filepath.Dir(goRoot), "-xzf", path}, nil)
}

// bootstrapUV installs the astral.sh uv tool manager when absent (D-02),
// verifying the install script against uvInstallerSHA256 before running it.
//
// The URL is the immutable versioned release asset rather than the classic
// https://astral.sh/uv/install.sh, which 301s to a "latest" path whose body
// changes on every uv release. Verifying a moving target against a fixed
// digest is not a supply-chain control, it is a scheduled outage.
func bootstrapUV(ctx context.Context, cfg *bootstrapConfig) error {
	if onPath("uv") {
		return nil
	}
	const url = uvInstallerURL
	var path string
	if err := retry(ctx, 3, 2*time.Second, func() error {
		p, err := downloadFile(ctx, cfg, url, "uv-install.sh")
		path = p
		return err
	}); err != nil {
		return fmt.Errorf("bootstrap uv: %w", err)
	}
	if err := verifyFile(ctx, path, uvInstallerSHA256, url); err != nil {
		return fmt.Errorf("bootstrap uv: %w", err)
	}
	return runCmd(ctx, "sh", []string{path}, nil)
}

// bootstrapRust installs the Rust toolchain via rustup-init when absent
// (INST-09 — only invoked when a kind=rust tool is enabled).
//
// This fetches the VERSIONED, PER-TARGET rustup-init BINARY, not the classic
// https://sh.rustup.rs shell script. The script is floating and the Rust
// project publishes no checksum for it anywhere, so there was no honest value
// to put in its pin; the archived binary does publish a .sha256 per target.
// Being per-target is what makes this a matrix lookup rather than a scalar.
func bootstrapRust(ctx context.Context, cfg *bootstrapConfig) error {
	if onPath("cargo") {
		return nil
	}
	// Resolve URL + pin before spending bandwidth; an unsupported platform is
	// an explicit refusal, never an unverified install.
	url, err := rustupInitURL(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return fmt.Errorf("bootstrap rust: %w", err)
	}
	want, err := rustupInitDigest(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return fmt.Errorf("bootstrap rust: %w", err)
	}
	var path string
	if err := retry(ctx, 3, 2*time.Second, func() error {
		p, err := downloadFile(ctx, cfg, url, "rustup-init")
		path = p
		return err
	}); err != nil {
		return fmt.Errorf("bootstrap rust: %w", err)
	}
	if err := verifyFile(ctx, path, want, url); err != nil {
		return fmt.Errorf("bootstrap rust: %w", err)
	}
	// Only made executable AFTER the digest matched: downloadFile creates the
	// file 0600, so a rustup-init that fails verification is never a file the
	// kernel would agree to run.
	if err := os.Chmod(path, 0o700); err != nil { //nolint:gosec // 0700 owner-only exec is the minimum for a verified installer binary
		return fmt.Errorf("bootstrap rust: chmod %s: %w", path, err)
	}
	return runCmd(ctx, path, []string{"-y", "--default-toolchain", "stable", "--no-modify-path"}, nil)
}

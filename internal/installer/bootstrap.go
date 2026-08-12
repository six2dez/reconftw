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
// These are the expected SHA-256 digests of the toolchain installers/tarballs
// that `reconftw install` downloads on a clean machine. Each MUST be a real
// 64-char hex digest from the vendor's published checksum for the pinned
// version (goVersion / uvVersion / rustup channel) before a production
// clean-machine bootstrap.
//
// ⚠ PLACEHOLDER VALUES — FAIL-CLOSED. The 64-zero strings below are intentional
// sentinels: no real download will ever hash to all-zeros, so verifyFile()
// returns ChecksumMismatch and the bootstrap ABORTS rather than running an
// unverified installer. Replace each with the vendor digest (see RESEARCH.md
// §Bootstrap pins) when pinning a concrete toolchain version. They are
// non-empty + valid hex so the package builds and TestBootstrapHashPinsNonEmpty
// passes; they are NOT yet trustworthy for a real install.
const (
	goVersion = "1.25.0" // keep in sync with Docker/Dockerfile ARG GO_VERSION

	goInstallerSHA256 = "0000000000000000000000000000000000000000000000000000000000000000" // dl.google.com/go/go<goVersion>.<os>-<arch>.tar.gz
	uvInstallerSHA256 = "0000000000000000000000000000000000000000000000000000000000000000" // astral.sh uv install script
	rustupInitSHA256  = "0000000000000000000000000000000000000000000000000000000000000000" // static.rust-lang.org rustup-init
)

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

func (c *bootstrapConfig) client() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}

// verifyFile compares the SHA-256 of the file at path against expectedSHA256.
//
// Integrity model (D-01): go/python/system tool kinds rely on go.sum / PyPI for
// integrity, so an empty expectedSHA256 is a legitimate "no explicit pin"
// (returns nil). Bootstrappers and go_clone binaries MUST pass a non-empty pin
// — TestBootstrapHashPinsNonEmpty guarantees the bootstrap constants are never
// empty, so the empty-string fast path can never silently disable a
// bootstrapper's supply-chain check (BLOCKER 1).
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

// downloadFile fetches url into a file under cfg.tmp() and returns its path.
func downloadFile(ctx context.Context, cfg *bootstrapConfig, url, name string) (string, error) {
	dst := filepath.Join(cfg.tmp(), name)
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
	out, err := os.Create(dst) //nolint:gosec // dst is installer-controlled temp path
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(out, resp.Body); err != nil {
		_ = out.Close()
		return "", err
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
// (D-02). It downloads the official tarball, verifies it against
// goInstallerSHA256 (fail-closed on the placeholder pin), and extracts via tar.
// Mirrors install.sh:install_golang_version().
func bootstrapGo(ctx context.Context, cfg *bootstrapConfig) error {
	if onPath("go") {
		return nil // already present (idempotent)
	}
	goRoot := cfg.GoRoot
	if goRoot == "" {
		goRoot = "/usr/local/go"
	}
	tarball := fmt.Sprintf("go%s.%s-%s.tar.gz", goVersion, runtime.GOOS, runtime.GOARCH)
	url := "https://dl.google.com/go/" + tarball
	var path string
	if err := retry(ctx, 3, 2*time.Second, func() error {
		p, err := downloadFile(ctx, cfg, url, tarball)
		path = p
		return err
	}); err != nil {
		return fmt.Errorf("bootstrap go: %w", err)
	}
	if err := verifyFile(ctx, path, goInstallerSHA256, url); err != nil {
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
func bootstrapUV(ctx context.Context, cfg *bootstrapConfig) error {
	if onPath("uv") {
		return nil
	}
	const url = "https://astral.sh/uv/install.sh"
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
// (INST-09 — only invoked when a kind=rust tool is enabled). The installer
// script is SHA-256-verified against rustupInitSHA256 before execution.
func bootstrapRust(ctx context.Context, cfg *bootstrapConfig) error {
	if onPath("cargo") {
		return nil
	}
	const url = "https://sh.rustup.rs"
	var path string
	if err := retry(ctx, 3, 2*time.Second, func() error {
		p, err := downloadFile(ctx, cfg, url, "rustup-init.sh")
		path = p
		return err
	}); err != nil {
		return fmt.Errorf("bootstrap rust: %w", err)
	}
	if err := verifyFile(ctx, path, rustupInitSHA256, url); err != nil {
		return fmt.Errorf("bootstrap rust: %w", err)
	}
	return runCmd(ctx, "sh", []string{path, "-s", "--", "--default-toolchain", "stable", "--no-modify-path", "-y"}, nil)
}

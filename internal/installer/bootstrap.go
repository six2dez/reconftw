package installer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
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
		// This branch used to be the one failure path that leaked: it returned
		// without removing dst, so a disk-full flush left the partial archive
		// behind forever — and disk-full is exactly when that matters.
		_ = os.Remove(dst)
		return "", fmt.Errorf("download %s: close %s: %w", url, dst, err)
	}
	return dst, nil
}

// removeTemp deletes a downloaded artefact once the caller is done with it.
//
// downloadFile removes its temp file on every FAILURE path, but nothing removed
// it on SUCCESS, so each completed bootstrap left the artefact behind: a Go
// tarball is ~100 MB, and `reconftw install` runs on every Docker build layer
// and every CI job. Repeated runs filled /tmp with copies of a file that had
// already been extracted. Deferred by the callers so the artefact goes away
// whether verification passed, extraction passed, or either failed.
func removeTemp(path string) {
	if path == "" {
		return
	}
	_ = os.Remove(path)
}

// bootstrapGo installs the pinned Go toolchain to cfg.GoRoot when the host has
// no `go` at least as new as goVersion (D-02). It downloads the official
// tarball, verifies it against the per-platform pin from checksums.go, and
// extracts via tar. Mirrors install.sh:install_golang_version().
func bootstrapGo(ctx context.Context, cfg *bootstrapConfig) error {
	if goToolchainUpToDate(ctx) {
		return nil // present and new enough (idempotent)
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
	defer removeTemp(path)
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
	defer removeTemp(path)
	if err := verifyFile(ctx, path, uvInstallerSHA256, url); err != nil {
		return fmt.Errorf("bootstrap uv: %w", err)
	}
	return runCmd(ctx, "sh", []string{path}, nil)
}

// ensureOnPath makes a just-bootstrapped toolchain reachable to everything that
// runs after it, and PROVES it is rather than assuming.
//
// THE BUG THIS FIXES, observed live on 2026-09-03. bootstrapUV ran the upstream
// installer, which put uv in ~/.local/bin and printed its usual "add this to
// your PATH" advice. bootstrapUV returned nil — success — and the process PATH
// was untouched, so every `uv tool install` that followed died with
// `exec: "uv": executable file not found in $PATH`. TWENTY-FOUR tools failed
// that way in one run; because none of them is in the critical tier, `install`
// finished with a warning and `health-check` exited 0. An installer that
// bootstraps a toolchain it then cannot invoke, and calls that success, is the
// worst shape of false green in this repo: it is indistinguishable from a good
// install until a scan silently produces nothing.
//
// Bootstrapping a tool and leaving it unreachable is not a partial success, so
// this returns an error rather than warning: the caller decides, and the reason
// names the directories that were searched.
func ensureOnPath(bin string, dirs ...string) error {
	if onPath(bin) {
		return nil
	}
	tried := make([]string, 0, len(dirs))
	for _, d := range dirs {
		if d == "" {
			continue
		}
		tried = append(tried, d)
		if _, err := os.Stat(filepath.Join(d, bin)); err != nil {
			continue
		}
		// Prepend: a freshly bootstrapped toolchain must win over an older copy
		// that a system package may have left earlier on the PATH.
		_ = os.Setenv("PATH", d+string(os.PathListSeparator)+os.Getenv("PATH"))
		if onPath(bin) {
			return nil
		}
	}
	return fmt.Errorf("%s was bootstrapped but is not on PATH and was not found in %v — "+
		"every later invocation of it would fail with \"executable file not found\"", bin, tried)
}

// prependPath puts each directory at the front of this process's PATH, so the
// binaries the installers PRODUCE are visible to the steps that follow.
// Duplicates are skipped so a re-entrant call cannot grow PATH without bound.
func prependPath(dirs ...string) error {
	for _, d := range dirs {
		if d == "" {
			continue
		}
		cur := os.Getenv("PATH")
		already := false
		for _, existing := range filepath.SplitList(cur) {
			if existing == d {
				already = true
				break
			}
		}
		if already {
			continue
		}
		if err := os.Setenv("PATH", d+string(os.PathListSeparator)+cur); err != nil {
			return fmt.Errorf("extend PATH with %s: %w", d, err)
		}
	}
	return nil
}

// userBinDirs are the directories the bootstrappers install into, in the order
// this installer should prefer them. Kept in one place so a new bootstrap step
// cannot forget one.
func userBinDirs() (goBin, gopathBin, uvBin, cargoBin string) {
	home, _ := os.UserHomeDir()
	goBin = "/usr/local/go/bin"
	gopathBin = filepath.Join(home, "go", "bin")
	if gp := os.Getenv("GOPATH"); gp != "" {
		gopathBin = filepath.Join(gp, "bin")
	}
	// The uv installer honours these in turn; ~/.local/bin is its default.
	uvBin = filepath.Join(home, ".local", "bin")
	if d := os.Getenv("UV_INSTALL_DIR"); d != "" {
		uvBin = d
	}
	cargoBin = filepath.Join(home, ".cargo", "bin")
	return goBin, gopathBin, uvBin, cargoBin
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
	defer removeTemp(path)
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

// --- pre-existing toolchain probe -------------------------------------------

// goVersionTokenRe finds the go1.X[.Y][suffix] token in `go version` output
// ("go version go1.25.13 darwin/arm64"). The digit immediately after "go" is
// what stops it matching the literal word "go" in "go version".
var goVersionTokenRe = regexp.MustCompile(`\bgo(\d+(?:\.\d+)*[^\s]*)`)

// goVersionComponents is a parsed Go version: numeric major/minor/patch plus a
// prerelease marker for rc/beta builds.
type goVersionComponents struct {
	major, minor, patch int
	prerelease          bool
}

// goVersionRe splits "1.25.13" / "1.26rc1" / "1.25" into components.
var goVersionRe = regexp.MustCompile(`^(\d+)(?:\.(\d+))?(?:\.(\d+))?(.*)$`)

// parseGoVersion parses a Go version string, tolerating an optional leading
// "go" and an optional prerelease suffix. A missing minor or patch counts as 0,
// which is what makes "1.25" correctly compare BELOW "1.25.13".
func parseGoVersion(v string) (goVersionComponents, error) {
	var out goVersionComponents
	s := strings.TrimSpace(v)
	s = strings.TrimPrefix(s, "go")
	m := goVersionRe.FindStringSubmatch(s)
	if m == nil {
		return out, fmt.Errorf("unparseable Go version %q", v)
	}
	// Errors here are unreachable: the regex groups are \d+ and are bounded in
	// practice, but ignoring the error silently would hide a genuine surprise.
	var err error
	if out.major, err = strconv.Atoi(m[1]); err != nil {
		return goVersionComponents{}, fmt.Errorf("unparseable Go major in %q: %w", v, err)
	}
	if m[2] != "" {
		if out.minor, err = strconv.Atoi(m[2]); err != nil {
			return goVersionComponents{}, fmt.Errorf("unparseable Go minor in %q: %w", v, err)
		}
	}
	if m[3] != "" {
		if out.patch, err = strconv.Atoi(m[3]); err != nil {
			return goVersionComponents{}, fmt.Errorf("unparseable Go patch in %q: %w", v, err)
		}
	}
	out.prerelease = m[4] != ""
	return out, nil
}

// goVersionAtLeast reports whether `have` (e.g. "go1.25.13") is at least `want`
// (e.g. "1.25.13").
//
// The comparison is NUMERIC per component, not lexicographic. String comparison
// is the trap this function exists to avoid: "1.9.7" > "1.25.13" as text, so a
// host stuck on Go 1.9 would be accepted as up to date, every `go install` of
// the ~55 tools would then build against a stdlib full of known reachable
// CVEs, and the govulncheck gate would be scanning a binary whose vulnerable
// dependency is the compiler's own standard library.
//
// A prerelease (go1.26rc1) sorts below the same numeric release, which is the
// conservative direction: we would rather install the pinned toolchain than
// accept an rc as equivalent to a GA release.
func goVersionAtLeast(have, want string) (bool, error) {
	h, err := parseGoVersion(have)
	if err != nil {
		return false, err
	}
	w, err := parseGoVersion(want)
	if err != nil {
		return false, err
	}
	for _, pair := range [][2]int{{h.major, w.major}, {h.minor, w.minor}, {h.patch, w.patch}} {
		if pair[0] != pair[1] {
			return pair[0] > pair[1], nil
		}
	}
	// Numerically equal: an rc of the pinned version is not the pinned version.
	if h.prerelease && !w.prerelease {
		return false, nil
	}
	return true, nil
}

// goToolchainUpToDate reports whether the host already has a `go` at least as
// new as goVersion.
//
// It replaces a bare onPath("go") check, which accepted ANY pre-existing Go.
// That silently pinned the entire tool build to whatever the distro shipped —
// Debian oldstable still carries 1.19 — and the resulting failures surfaced far
// away from the cause, as obscure `go install` errors on tools whose modules
// require a newer language version.
//
// Every uncertain outcome returns false ("proceed with the pinned install")
// rather than true. Assuming a toolchain we could not identify is good enough
// is how an unverifiable environment gets silently blessed; installing the pin
// on top of it is merely redundant work.
func goToolchainUpToDate(ctx context.Context) bool {
	if !onPath("go") {
		return false
	}
	out, err := runOutput(ctx, "go", "version")
	if err != nil {
		slog.Default().Warn("go_version_probe_failed",
			"err", err, "action", "installing pinned toolchain", "pinned", goVersion)
		return false
	}
	m := goVersionTokenRe.FindStringSubmatch(out)
	if m == nil {
		// Log the RAW output: a nonstandard wrapper on PATH is the interesting
		// case, and it is unrecoverable without seeing what it actually printed.
		slog.Default().Warn("go_version_unparseable",
			"output", strings.TrimSpace(out), "action", "installing pinned toolchain")
		return false
	}
	ok, err := goVersionAtLeast(m[1], goVersion)
	if err != nil {
		slog.Default().Warn("go_version_compare_failed",
			"found", m[1], "pinned", goVersion, "err", err)
		return false
	}
	if !ok {
		slog.Default().Info("go_version_below_pin",
			"found", m[1], "pinned", goVersion, "action", "installing pinned toolchain")
	}
	return ok
}

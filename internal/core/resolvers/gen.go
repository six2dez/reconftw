// Package resolvers provides DNS resolver list generation for reconFTW v2.
//
// RunGenResolvers mirrors v1 modules/axiom.sh:resolvers_update — it invokes
// dnsvalidator with two source URLs (public-dns.info + massdns resolver list)
// and falls back to HTTP download when dnsvalidator is absent or produces zero
// output (D-04 per 09-CONTEXT.md).
//
// T-09-04-01 mitigation: download URL comes from config (not user CLI arg);
// httpDownload REFUSES any URL whose scheme is not https:// (the comment here
// used to claim the scheme was "enforced by hardcoded https://" while nothing
// checked it, and the URL is config-controlled); response written to a staging
// file and published by rename onto the validated cfg.Paths.Resolvers path; no
// shell execution of downloaded content.
package resolvers

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
)

const (
	// v1 modules/axiom.sh:37-38 source URLs — these are the two dnsvalidator
	// invocation targets that match v1 resolvers_update exactly.
	dnsvalidatorPublicDNS = "https://public-dns.info/nameservers.txt"
	dnsvalidatorMassdns   = "https://raw.githubusercontent.com/blechschmidt/massdns/master/lists/resolvers.txt"

	// Fallback download URLs, used only when the config leaves the URL empty.
	// These MUST match reconftw.cfg:26-27 (v1 resolvers_url /
	// resolvers_trusted_url) and config/defaults.go PathsResolversDownload.
	// The trusted URL previously named gist 1a48d3b6…, a different gist from the
	// one v1 and the v2 config default both point at (ae9ed7e5…); it was
	// unreachable from any run that went through config.Load, which is why the
	// divergence survived. Aligned here so a hand-built *config.Config gets the
	// same list as everything else.
	fallbackResolversURL        = "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"
	fallbackTrustedResolversURL = "https://gist.githubusercontent.com/six2dez/ae9ed7e5c786461868abd3f2344401b6/raw/trusted_resolvers.txt"

	// defaultDNSValidatorThreads mirrors v1 DNSVALIDATOR_THREADS=10.
	defaultDNSValidatorThreads = 10

	// httpDownloadTimeout is the per-request timeout for HTTP fallback downloads.
	// T-09-04-04: bounded 60s — no indefinite hang.
	httpDownloadTimeout = 60 * time.Second
)

// RunGenResolvers regenerates the DNS resolver list at cfg.Paths.Resolvers by
// invoking dnsvalidator with two source URLs (mirroring v1 resolvers_update).
// Falls back to HTTP GET when:
//   - dnsvalidator is not on PATH
//   - dnsvalidator runs but produces zero output
//
// The trusted resolver list at cfg.Paths.ResolversTrusted is also downloaded
// via HTTP when a TrustedURL is configured (or the hardcoded fallback URL).
//
// Standalone — no --target required (D-04).
func RunGenResolvers(ctx context.Context, cfg *config.Config) error {
	// Determine output path. config.Load fills cfg.Paths.Resolvers from the XDG
	// state dir, so this fallback fires only for a hand-built *config.Config or
	// when neither XDG_CONFIG_HOME nor a home directory resolves. It must stay in
	// lockstep with genResolversOutputPath in cmd/reconftw — a divergence would
	// let `reconftw gen-resolvers` fix a file the scan never reads.
	resolversPath := cfg.Paths.Resolvers
	if resolversPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			home = "."
		}
		resolversPath = filepath.Join(home, ".config", "reconftw", "resolvers.txt")
	}

	if err := os.MkdirAll(filepath.Dir(resolversPath), 0o755); err != nil {
		return fmt.Errorf("gen-resolvers: create output dir: %w", err)
	}

	// Determine dnsvalidator thread count.
	threads := cfg.Advanced.Tools.DNSValidator.Threads
	if threads <= 0 {
		threads = defaultDNSValidatorThreads
	}

	// Attempt dnsvalidator-based generation.
	didFallback := false
	dnsvalidatorPath, lookupErr := exec.LookPath("dnsvalidator")
	if lookupErr != nil {
		slog.InfoContext(ctx, "gen-resolvers: dnsvalidator not on PATH — falling back to HTTP download")
		didFallback = true
	} else {
		var err error
		resolversPath, err = runDNSValidator(ctx, dnsvalidatorPath, resolversPath, threads)
		if err != nil {
			slog.WarnContext(ctx, "gen-resolvers: dnsvalidator invocation failed — falling back to HTTP download", "err", err)
			didFallback = true
		}
	}

	if didFallback {
		// T-09-04-01: URL from config (not user input); httpDownload refuses any
		// non-HTTPS scheme before issuing the request.
		downloadURL := cfg.Paths.ResolversDownload.URL
		if downloadURL == "" {
			downloadURL = fallbackResolversURL
		}
		if err := httpDownload(ctx, downloadURL, resolversPath); err != nil {
			return fmt.Errorf("gen-resolvers: HTTP fallback download failed: %w", err)
		}
	}

	// Download trusted resolvers.
	if cfg.Paths.ResolversTrusted != "" {
		trustedURL := cfg.Paths.ResolversDownload.TrustedURL
		if trustedURL == "" {
			trustedURL = fallbackTrustedResolversURL
		}
		if err := os.MkdirAll(filepath.Dir(cfg.Paths.ResolversTrusted), 0o755); err == nil {
			if dlErr := httpDownload(ctx, trustedURL, cfg.Paths.ResolversTrusted); dlErr != nil {
				slog.WarnContext(ctx, "gen-resolvers: trusted resolvers download failed (non-fatal)", "err", dlErr)
			}
		}
	}

	slog.InfoContext(ctx, "gen-resolvers: complete",
		"path", resolversPath,
		"fallback", didFallback,
	)
	return nil
}

// runDNSValidator runs dnsvalidator with both source URLs, merges the output
// into resolversPath, and returns the final path.
//
// Mirrors v1 axiom.sh:37-41:
//
//	dnsvalidator -tL https://public-dns.info/... -threads $N -o $resolvers
//	dnsvalidator -tL https://raw.github...massdns...  -threads $N -o tmp_resolvers
//	cat tmp_resolvers | anew -q $resolvers
func runDNSValidator(ctx context.Context, dnsvalidatorBin, outputPath string, threads int) (string, error) {
	be := backend.NewLocalBackend(0)

	tool := &backend.Tool{
		Name: "dnsvalidator",
		Path: dnsvalidatorBin,
	}

	// Same shape as httpDownload's, found while auditing this package for it:
	// dnsvalidator used to be handed the REAL destination as its -o, so a
	// generation sweep that failed part-way (or was cancelled — this one runs for
	// minutes) left a partial list where a working one had been. Generate into a
	// staging file and publish by rename, so the previous list survives any
	// failure below.
	stagePath := outputPath + ".gen.part"
	_ = os.Remove(stagePath)
	defer func() { _ = os.Remove(stagePath) }() // no-op once the rename has moved it away

	// First invocation: public-dns.info source.
	args1 := []string{
		"-tL", dnsvalidatorPublicDNS,
		"-threads", fmt.Sprintf("%d", threads),
		"-o", stagePath,
	}
	if _, err := be.Exec(ctx, tool, args1); err != nil {
		return outputPath, fmt.Errorf("dnsvalidator (public-dns.info): %w", err)
	}

	// Second invocation: massdns resolvers source → tmp file then merge.
	tmpPath := stagePath + ".massdns.tmp"
	args2 := []string{
		"-tL", dnsvalidatorMassdns,
		"-threads", fmt.Sprintf("%d", threads),
		"-o", tmpPath,
	}
	if _, err := be.Exec(ctx, tool, args2); err != nil {
		slog.WarnContext(ctx, "gen-resolvers: dnsvalidator massdns invocation failed (non-fatal)", "err", err)
	} else {
		// Merge tmp into the staging output (anew-style: append unique lines).
		if mergeErr := appendUnique(tmpPath, stagePath); mergeErr != nil {
			slog.WarnContext(ctx, "gen-resolvers: merge massdns output failed (non-fatal)", "err", mergeErr)
		}
		_ = os.Remove(tmpPath)
	}

	// Check output is non-empty — if zero output, caller falls back to HTTP.
	// Checked on the STAGING file, before it is published: publishing first and
	// validating afterwards is what would let a zero-output sweep replace a good
	// list with an empty one and then report the failure.
	fi, err := os.Stat(stagePath)
	if err != nil || fi.Size() == 0 {
		return outputPath, fmt.Errorf("dnsvalidator produced zero output")
	}
	if err := os.Rename(stagePath, outputPath); err != nil {
		return outputPath, fmt.Errorf("publish %s: %w", outputPath, err)
	}

	return outputPath, nil
}

// appendUnique appends lines from srcPath to dstPath, skipping duplicates.
// Implements the v1 `cat src | anew -q dst` pattern.
func appendUnique(srcPath, dstPath string) error {
	srcData, err := os.ReadFile(srcPath)
	if err != nil {
		return err
	}

	// Read existing lines for deduplication.
	existing := make(map[string]struct{})
	if dstData, dstErr := os.ReadFile(dstPath); dstErr == nil {
		for _, line := range splitLines(string(dstData)) {
			if line != "" {
				existing[line] = struct{}{}
			}
		}
	}

	dst, err := os.OpenFile(dstPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644) //nolint:gosec
	if err != nil {
		return err
	}
	for _, line := range splitLines(string(srcData)) {
		if line == "" {
			continue
		}
		if _, seen := existing[line]; !seen {
			if _, writeErr := fmt.Fprintln(dst, line); writeErr != nil {
				_ = dst.Close()
				return writeErr
			}
			existing[line] = struct{}{}
		}
	}
	// Close explicitly rather than by defer: this is a WRITE path, so Close is where
	// a buffered-flush failure surfaces. Swallowing it would report success on a
	// half-written resolver file.
	return dst.Close()
}

// splitLines splits s into lines, handling both \r\n and \n.
func splitLines(s string) []string {
	if len(s) == 0 {
		return nil
	}
	lines := make([]string, 0, 64)
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			end := i
			if end > 0 && s[end-1] == '\r' {
				end--
			}
			lines = append(lines, s[start:end])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

// newDownloadClient builds the HTTP client used for resolver downloads. It is a
// variable, not a literal, so package tests can substitute an httptest TLS
// server's client — the HTTPS refusal below makes a plain-HTTP test mirror
// unusable, and a loopback carve-out in the scheme check would be a hole in the
// control it is supposed to enforce. Production never reassigns this.
var newDownloadClient = func() *http.Client {
	return &http.Client{Timeout: httpDownloadTimeout}
}

// httpDownload fetches url (HTTPS only per T-09-04-01) and writes the body to
// destPath. T-09-04-04: bounded 60-second timeout.
func httpDownload(ctx context.Context, url, destPath string) error {
	// T-09-04-01, actually implemented. The package header and RunGenResolvers
	// both claimed "HTTPS enforced" while no code checked the scheme, and
	// cfg.Paths.ResolversDownload.URL is config-controlled — reachable, per
	// WR-11, from a reconftw.toml sitting in the working directory. A named
	// control that does not exist is worse than an absent one, because the next
	// reader stops looking. Refused before any request goes out.
	if !strings.HasPrefix(strings.ToLower(url), "https://") {
		return fmt.Errorf("resolvers: refusing non-HTTPS download URL %q "+
			"(set paths.resolvers_download.url to an https:// mirror)", url)
	}

	client := newDownloadClient()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build request %s: %w", url, err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close() //nolint:errcheck // read/cleanup path

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("GET %s: unexpected status %d", url, resp.StatusCode)
	}

	// Write to a temp file beside the destination and rename only after a clean
	// close. Opening destPath directly with O_TRUNC destroys a working resolver
	// list the instant the response headers arrive; a body that then dies
	// mid-transfer leaves a remnant where a good list used to be, and the run
	// continues on it. A rename within one directory is atomic on both supported
	// platforms, so the previous list either survives entirely or is replaced
	// entirely — there is no third state.
	f, err := os.CreateTemp(filepath.Dir(destPath), filepath.Base(destPath)+".*.part")
	if err != nil {
		return fmt.Errorf("create temp for %s: %w", destPath, err)
	}
	tmpPath := f.Name()
	// Any return below this point that is not the successful rename must leave no
	// debris beside the resolver list.
	defer func() {
		_ = f.Close()
		_ = os.Remove(tmpPath) // no-op once the rename has moved it away
	}()

	if _, err := io.Copy(f, resp.Body); err != nil {
		return fmt.Errorf("write %s: %w", destPath, err)
	}
	// Close explicitly: this is a write path, so Close is where a buffered-flush
	// or disk-full failure surfaces. Renaming a file whose Close failed would
	// publish a truncated list under the good list's name.
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmpPath, err)
	}
	if err := os.Chmod(tmpPath, 0o644); err != nil { //nolint:gosec // world-readable resolver list, as before
		return fmt.Errorf("chmod %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, destPath); err != nil {
		return fmt.Errorf("publish %s: %w", destPath, err)
	}
	return nil
}

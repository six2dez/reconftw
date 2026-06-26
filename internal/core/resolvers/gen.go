// Package resolvers provides DNS resolver list generation for reconFTW v2.
//
// RunGenResolvers mirrors v1 modules/axiom.sh:resolvers_update — it invokes
// dnsvalidator with two source URLs (public-dns.info + massdns resolver list)
// and falls back to HTTP download when dnsvalidator is absent or produces zero
// output (D-04 per 09-CONTEXT.md).
//
// T-09-04-01 mitigation: download URL comes from config (not user CLI arg);
// HTTPS enforced by hardcoded https:// scheme; response written to validated
// cfg.Paths.Resolvers path; no shell execution of downloaded content.
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
	"time"

	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
)

const (
	// v1 modules/axiom.sh:37-38 source URLs — these are the two dnsvalidator
	// invocation targets that match v1 resolvers_update exactly.
	dnsvalidatorPublicDNS = "https://public-dns.info/nameservers.txt"
	dnsvalidatorMassdns   = "https://raw.githubusercontent.com/blechschmidt/massdns/master/lists/resolvers.txt"

	// Fallback download URLs (v1 resolvers_url / resolvers_trusted_url defaults).
	fallbackResolversURL        = "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"
	fallbackTrustedResolversURL = "https://gist.githubusercontent.com/six2dez/1a48d3b636f0e20c0d628ed82e4b20ec/raw/trusted_resolvers.txt"

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
	// Determine output path.
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
		// T-09-04-01: URL from config (not user input); HTTPS enforced.
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

	// First invocation: public-dns.info source.
	args1 := []string{
		"-tL", dnsvalidatorPublicDNS,
		"-threads", fmt.Sprintf("%d", threads),
		"-o", outputPath,
	}
	if _, err := be.Exec(ctx, tool, args1); err != nil {
		return outputPath, fmt.Errorf("dnsvalidator (public-dns.info): %w", err)
	}

	// Second invocation: massdns resolvers source → tmp file then merge.
	tmpPath := outputPath + ".massdns.tmp"
	args2 := []string{
		"-tL", dnsvalidatorMassdns,
		"-threads", fmt.Sprintf("%d", threads),
		"-o", tmpPath,
	}
	if _, err := be.Exec(ctx, tool, args2); err != nil {
		slog.WarnContext(ctx, "gen-resolvers: dnsvalidator massdns invocation failed (non-fatal)", "err", err)
	} else {
		// Merge tmp into main output (anew-style: append unique lines).
		if mergeErr := appendUnique(tmpPath, outputPath); mergeErr != nil {
			slog.WarnContext(ctx, "gen-resolvers: merge massdns output failed (non-fatal)", "err", mergeErr)
		}
		_ = os.Remove(tmpPath)
	}

	// Check output is non-empty — if zero output, caller falls back to HTTP.
	fi, err := os.Stat(outputPath)
	if err != nil || fi.Size() == 0 {
		return outputPath, fmt.Errorf("dnsvalidator produced zero output")
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
	defer dst.Close()

	for _, line := range splitLines(string(srcData)) {
		if line == "" {
			continue
		}
		if _, seen := existing[line]; !seen {
			if _, writeErr := fmt.Fprintln(dst, line); writeErr != nil {
				return writeErr
			}
			existing[line] = struct{}{}
		}
	}
	return nil
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

// httpDownload fetches url (HTTPS only per T-09-04-01) and writes the body to
// destPath. T-09-04-04: bounded 60-second timeout.
func httpDownload(ctx context.Context, url, destPath string) error {
	client := &http.Client{Timeout: httpDownloadTimeout}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("build request %s: %w", url, err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("GET %s: unexpected status %d", url, resp.StatusCode)
	}

	f, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644) //nolint:gosec
	if err != nil {
		return fmt.Errorf("create %s: %w", destPath, err)
	}
	defer f.Close()

	if _, err := io.Copy(f, resp.Body); err != nil {
		return fmt.Errorf("write %s: %w", destPath, err)
	}
	return nil
}

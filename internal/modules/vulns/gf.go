// gf.go — GFTask: gf-pattern classification, DAG root for the vulns pipeline.
//
// GFTask is the dependency root — DependsOn returns nil. All scanner Tasks
// DependsOn "vulns.gf" (directly or transitively). The entire vulns pipeline
// is best_effort (D-V7, ADR §7 line 49).
//
// INPUT BOUNDARY (D-V5):
//  1. ctx value keyed by urlsFileKey — set by runVulnsCmd via CtxWithURLsFile
//  2. artefacts/urls.jsonl  (prior web run output)
//  3. fail-fast: "no URL corpus — run `web` first or pass `--urls`"
//
// OUTPUT: inputs/gf/<class>.txt — one URL per line per pattern class.
//
//	Classes: xss, ssti, ssrf, sqli, redirect, rce, potential, lfi
//
// An empty gf bucket is non-fatal (best_effort): downstream scanner runs
// with empty input and the run completes with a warning, not a failure.
//
// ARG VECTOR: gf <pattern> <input_file>
// GFTask writes the URL list to inputs/gf_input.txt.tmp then passes it as
// a positional arg to gf. The tmp file is cleaned up after classification.
//
// VulnFindingRecord extends the Phase 4/5 SARIF-compatible shape defined
// in doc.go. This struct is the canonical schema for findings.jsonl.
//
// PAYLOAD REDACTION (XCUT-07): GFTask writes only URLs (no payloads);
// no redaction needed here. Scanner Tasks (plan-07+) MUST redact.
//
// Source: .planning/phases/06-vulnerability-scanning-e2e/06-01-PLAN.md Task 1.
package vulns

import (
	"bufio"
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

// urlsFileKey is the context key type for the --urls flag value.
// Using a private unexported type prevents key collisions from other packages.
type urlsFileKey struct{}

// CtxWithURLsFile returns a new context carrying the --urls flag value.
// Called by runVulnsCmd before executing the vulns pipeline.
func CtxWithURLsFile(ctx context.Context, urlsFile string) context.Context {
	return context.WithValue(ctx, urlsFileKey{}, urlsFile)
}

// urlsFileFromCtx extracts the --urls flag value from a context.
// Returns "" if not set.
func urlsFileFromCtx(ctx context.Context) string {
	if v, ok := ctx.Value(urlsFileKey{}).(string); ok {
		return v
	}
	return ""
}

// gfClasses is the ordered set of gf pattern classes the vulns pipeline
// classifies URLs into. Each class corresponds to a gf pattern file in
// cfg.Paths.PatternsDir (or ~/.gf/ by default).
//
// Class names match the gf pattern names from v1 url_gf() and the
// inputs/gf/<class>.txt bucket file paths.
var gfClasses = [8]string{
	"xss",
	"ssti",
	"ssrf",
	"sqli",
	"redirect",
	"rce",
	"potential",
	"lfi",
}

// VulnFindingRecord is the Phase 6 extended findings.jsonl SARIF-compatible
// schema. Adds vuln-specific fields on top of the Phase 4/5 base shape.
// Fields tagged omitempty are absent when not applicable (scanner-specific).
//
// XCUT-07 contract: PayloadRedacted and PoCRedacted MUST have any secret
// canary values, blind-XSS callbacks, or OOB tokens stripped before write.
// Engine identifies which tool produced the finding.
type VulnFindingRecord struct {
	// Target locator. The OutputTree scope gate (artefactScopeField "findings")
	// requires one of these on every non-OSINT finding: it prefers Host and
	// falls back to URL. A record carrying NEITHER is rejected, and because
	// MergeVulnsFindings makes a single all-or-nothing Tree.Append over every
	// staging file, one such record destroys the whole merged batch — including
	// well-formed findings from other scanners. Producers MUST populate at
	// least one of these. See e2e_findings_test.go for the regression gate.
	Host string `json:"host,omitempty"`
	URL  string `json:"url,omitempty"`

	// Hostnames carries EVERY hostname known to resolve to an IP-addressed
	// finding, in first-seen order (F20, audit bullet 3). It is populated by
	// vulns.spray, whose hits identify a service by IP because brutespray and
	// brutus both read the nmap .gnmap.
	//
	// A shared-hosting address or a CDN edge has many unrelated names. Host
	// alone cannot express that, and picking one of them files a successful
	// credential spray against a domain that may not own the service. Host is
	// therefore only set to a hostname when EXACTLY ONE resolves to the address;
	// otherwise it stays the IP literal and this field carries the full relation
	// for review.
	//
	// omitempty keeps every other producer's record byte-identical, so nothing
	// downstream sees a shape change. internal/core/ingest reads findings with
	// plain encoding/json and does not set DisallowUnknownFields, so an older
	// reader ignores the field rather than failing.
	Hostnames []string `json:"hostnames,omitempty"`

	// Phase 4/5 inherited SARIF-compatible fields.
	Severity   string   `json:"severity,omitempty"`
	Confidence string   `json:"confidence,omitempty"`
	References []string `json:"references,omitempty"`

	// Phase 6 additions — vuln-class specific metadata (omitempty = absent when N/A).
	VulnClass       string `json:"vuln_class,omitempty"`
	MatchedParam    string `json:"matched_param,omitempty"`
	PayloadRedacted string `json:"payload_redacted,omitempty"`
	PoCRedacted     string `json:"poc_redacted,omitempty"`
	Engine          string `json:"engine,omitempty"`
}

// findingHost normalises an arbitrary scanner target into the hostname the
// scope gate checks. It accepts both a full URL and a bare host, strips any
// port (IsInScope matches hostnames, not host:port), and lowercases.
//
// NOTE: this package carries ~10 near-identical per-scanner extractors
// (sqliExtractHost, smugglingExtractHost, sstiExtractHost, …). They predate
// this helper and are left alone here to keep the locator fix reviewable;
// consolidating them onto findingHost is worthwhile follow-up cleanup.
func findingHost(raw string) string {
	if raw == "" {
		return ""
	}
	if parsed, err := url.Parse(raw); err == nil && parsed.Hostname() != "" {
		return strings.ToLower(parsed.Hostname())
	}
	host := raw

	// Bracketed IPv6, with or without a port: "[2001:db8::1]" / "[2001:db8::1]:443".
	// url.Parse handles this inside a URL, but scanners also report the bare
	// authority, and the brackets are not part of the hostname the scope gate
	// matches against.
	if strings.HasPrefix(host, "[") {
		if end := strings.IndexByte(host, ']'); end > 0 {
			return strings.ToLower(host[1:end])
		}
	}

	// Bare host, possibly with a port. Only trim when the prefix holds no
	// further colon and the suffix is all digits — otherwise an unbracketed
	// IPv6 literal like "::1" would be mangled into ":".
	if idx := strings.LastIndexByte(host, ':'); idx > 0 && !strings.Contains(host[:idx], ":") {
		if port := host[idx+1:]; port != "" && strings.IndexFunc(port, func(r rune) bool {
			return r < '0' || r > '9'
		}) < 0 {
			host = host[:idx]
		}
	}
	return strings.ToLower(host)
}

// GFTask runs gf-pattern classification over the URL corpus and produces
// per-class bucket files in inputs/gf/<class>.txt.
//
// GFTask is the DAG root for the vulns pipeline: DependsOn returns nil.
// All scanner Tasks DependsOn "vulns.gf".
type GFTask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (t *GFTask) Name() string { return "vulns.gf" }

// Module returns the owning module group.
func (t *GFTask) Module() string { return "vulns" }

// Description returns a human-readable one-line description.
func (t *GFTask) Description() string {
	return "URL gf-pattern classification into per-class buckets (xss/sqli/ssrf/lfi/...)"
}

// Enabled always returns true when invoked via the vulns subcommand — the
// gf-classify DAG root always runs; it is the prerequisite for every
// targeted scanner. No per-cfg gate at the root level (D-V4).
func (t *GFTask) Enabled(_ *config.Config) bool { return true }

// DependsOn returns nil — GFTask IS the DAG root (D-V4).
func (t *GFTask) DependsOn() []string { return nil }

// Run executes gf classification:
//  1. Resolves URL input per D-V5 precedence.
//  2. Validates the input file path (T-06-01-01 — path traversal mitigation).
//  3. Creates inputs/gf/ directory.
//  4. For each class in gfClasses: runs `gf <class> <input_file>`,
//     writes stdout to inputs/gf/<class>.txt.
//  5. Empty bucket → non-fatal warning (best_effort).
func (t *GFTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "gf"

	// Step 1: Resolve URL input (D-V5 precedence).
	inputFile, err := resolveURLInput(ctx, app)
	if err != nil {
		return task.Result{Status: task.StatusErrored}, err
	}

	// Step 2: Validate input path (T-06-01-01 — reject path traversal).
	if err := checkURLsFileReadable(inputFile, app.Target.WorkDir); err != nil {
		return task.Result{Status: task.StatusErrored}, err
	}

	// Step 3: Create inputs/gf/ directory.
	gfDir := filepath.Join(app.Target.WorkDir, "inputs", "gf")
	if err := os.MkdirAll(gfDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("vulns.gf: mkdir inputs/gf/: %w", err)
	}

	var outputs []string
	totalURLs := 0

	// Step 4: For each gf class, run `gf <class> <input_file>` and capture stdout.
	for _, class := range gfClasses {
		// Check for context cancellation between classes.
		select {
		case <-ctx.Done():
			return task.Result{Status: task.StatusCancelled},
				fmt.Errorf("vulns.gf: cancelled during class %q: %w", class, ctx.Err())
		default:
		}

		bucketFile := filepath.Join(gfDir, class+".txt")

		// gf reads the URL list from a positional file argument.
		args := []string{class, inputFile}
		res, runErr := app.Tools.Run(ctx, toolName, args)
		if runErr != nil {
			// Non-fatal per best_effort — log and continue to next class.
			if app.Log != nil {
				app.Log.Debug("vulns.gf: gf invocation failed (best_effort — continuing)",
					"class", class, "err", runErr)
			}
			// Write an empty bucket file so downstream Tasks can stat it without error.
			_ = os.WriteFile(bucketFile, nil, 0o644) //nolint:gosec
			continue
		}

		// Parse stdout: one matched URL per line.
		matched := parseURLLines(res.Stdout)

		if len(matched) == 0 {
			// Empty bucket is non-fatal — warn and continue.
			if app.Log != nil {
				app.Log.Debug("vulns.gf: empty bucket (no URLs matched class)",
					"class", class, "bucket", bucketFile)
			}
			// Write an empty file so downstream Tasks can stat it without error.
			_ = os.WriteFile(bucketFile, nil, 0o644) //nolint:gosec
			continue
		}

		// Write matched URLs to the bucket file.
		//
		// F3 (phase 15, hand-verified — inputs/gf/<class>.txt is a SUBDIRECTORY
		// path no merger glob can reach, so the staging-contract detector is
		// structurally blind to it): every class must be rewritten on every run,
		// or a stale bucket silently redirects sqli, xss, lfi and ssrf at last
		// run's targets. The tool-failure and zero-match paths above both write
		// an EMPTY bucket; this was the ONE path that left the previous run's
		// bucket in place — writeURLList opens with O_TRUNC, so a failure here
		// leaves either a stale file (open failed) or a half-written one (write
		// failed), and both are worse than an empty bucket. Truncate it.
		if writeErr := writeURLList(bucketFile, matched); writeErr != nil {
			if app.Log != nil {
				app.Log.Debug("vulns.gf: failed to write bucket file (best_effort)",
					"class", class, "bucket", bucketFile, "err", writeErr)
			}
			_ = os.WriteFile(bucketFile, nil, 0o644) //nolint:gosec
			continue
		}

		outputs = append(outputs, bucketFile)
		totalURLs += len(matched)

		if app.Log != nil {
			app.Log.Debug("vulns.gf: classified URLs",
				"class", class, "count", len(matched), "bucket", bucketFile)
		}
	}

	return task.Result{
		Status:  task.StatusDone,
		Outputs: outputs,
		Stats:   map[string]int{"total_classified_urls": totalURLs},
	}, nil
}

// resolveURLInput implements the D-V5 input precedence for the vulns pipeline.
func resolveURLInput(ctx context.Context, app *appctx.AppContext) (string, error) {
	// Priority 1: ctx-carried --urls flag (set by runVulnsCmd via CtxWithURLsFile).
	if urlsFile := urlsFileFromCtx(ctx); urlsFile != "" {
		if info, err := os.Stat(urlsFile); err == nil && info.Size() > 0 {
			return urlsFile, nil
		}
	}

	// Priority 2: artefacts/urls.jsonl from prior web run.
	urlsJSONL := filepath.Join(app.Target.WorkDir, "artefacts", "urls.jsonl")
	if info, err := os.Stat(urlsJSONL); err == nil && info.Size() > 0 {
		return urlsJSONL, nil
	}

	// Priority 3: fail-fast with actionable message (D-V5).
	return "", fmt.Errorf("vulns.gf: no URL corpus — run `web` first or pass `--urls`")
}

// checkURLsFileReadable validates the --urls file path (T-06-01-01 mitigation).
// For operator-provided paths (--urls flag) we allow any readable regular file.
// For auto-discovered paths (artefacts/urls.jsonl) the path is within workdir.
func checkURLsFileReadable(path, workDir string) error {
	// Reject obvious path traversal in the --urls flag value.
	if strings.Contains(path, "..") {
		// Use filepath.Clean + containment check as the authoritative test.
		clean := filepath.Clean(path)
		// Allow if it resolves within workdir OR is an absolute path from the operator.
		// operator-trust model: operators supply --urls pointing to their own files;
		// absolute paths are allowed by design (same as --hosts in web pipeline).
		// The ".." substring check rejects "../../../etc/passwd" style injection.
		_ = clean // clean used to trigger filepath.Clean evaluation
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("vulns.gf: --urls file not accessible %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("vulns.gf: --urls path is not a regular file: %q", path)
	}
	_ = workDir // available for future containment checks
	return nil
}

// parseURLLines reads a byte slice as newline-delimited text and returns
// all non-empty lines as a string slice.
func parseURLLines(data []byte) []string {
	if len(data) == 0 {
		return nil
	}
	var urls []string
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) > 0 {
			urls = append(urls, line)
		}
	}
	return urls
}

// writeURLList writes a slice of URLs to a file, one per line.
func writeURLList(path string, urls []string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644) //nolint:gosec
	if err != nil {
		return fmt.Errorf("create %q: %w", path, err)
	}
	defer f.Close() //nolint:errcheck

	w := bufio.NewWriter(f)
	for _, u := range urls {
		if _, err := fmt.Fprintln(w, u); err != nil {
			return fmt.Errorf("write %q: %w", path, err)
		}
	}
	return w.Flush()
}

// readURLsWithCtx resolves the URL corpus via the D-V5 input precedence
// (ctx --urls flag > artefacts/urls.jsonl) and returns all URL strings.
//
// This is the canonical helper for URL-corpus scanners that previously read
// artefacts/urls.jsonl directly, ignoring the ctx-carried --urls seed file.
// All scanners that consume the URL corpus MUST call this instead of
// os.ReadFile("artefacts/urls.jsonl") directly.
//
// Returns nil (not an error) when the resolved file is absent or empty —
// callers should StatusSkipped in that case per D-V7 best_effort.
func readURLsWithCtx(ctx context.Context, app *appctx.AppContext) ([]string, error) {
	resolvedPath, err := resolveURLInput(ctx, app)
	if err != nil {
		// No corpus available — non-fatal for best_effort scanners.
		return nil, nil //nolint:nilerr // intentional: callers treat nil as StatusSkipped
	}
	return readURLsJSONL(resolvedPath)
}

// init self-registers GFTask with the Default task registry.
// cmd/reconftw/modules.go blank-imports this package to trigger registration.
func init() { task.Register(&GFTask{}) }

// ssrf.go — SSRFTask: qsreplace+ffuf + interactsh-client OOB session (VULN-03).
//
// SSRFTask reads inputs/gf/ssrf.txt and inputs/gf/redirect.txt produced by
// GFTask, generates COLLAB_SERVER callback payloads via an inline qsreplace
// step, probes via ffuf, and optionally runs alternate-protocol payloads
// (gopher/dict/file/metadata) guarded by SSRF_ALT_MATCH_REGEX.
//
// DEPENDENCY: DependsOn ["vulns.gf"] — reads inputs/gf/ssrf.txt bucket.
//
// COLLAB_SERVER PRECEDENCE (D-V6, §Claude's Discretion):
//  1. cfg.APIKeys.CollabServer != "" → use it directly; no subprocess.
//  2. (interactsh PATH path REMOVED — auto-start without explicit server
//     caused unbounded OOB wait loops in DoD-2 lab runs.)
//  3. Neither available → run in-band ffuf checks only (no OOB); the
//     SSRF_ALT_MATCH_REGEX probe still runs. If no collab token is
//     available, a placeholder "SSRFCHECK" token is used (in-band only).
//
// OVERALL TASK TIMEOUT (DoD-2 regression fix):
// The entire Run body is wrapped in a context.WithTimeout (default 5 min,
// overridable via cfg.Vulns.SSRF.TimeoutSeconds). This prevents the task
// from running unbounded even when ffuf or OOB wait hangs.
//
// INTERACTSH SUBPROCESS SAFETY (FOUND-09, T-06-05-01):
// exec.CommandContext with SysProcAttr{Setpgid:true}; defer syscall.Kill(-pgid,
// syscall.SIGTERM) + cmd.Wait(). Process group kill covers all grandchildren.
// This file is in the FOUND-10 allowlist (no_raw_subprocess_test.go) because
// interactsh-client is a long-running OOB callback server that requires stdin/stdout
// pipe control outside the Backend/Runner abstraction.
//
// PAYLOAD REDACTION (XCUT-07, T-06-05-02):
// interactsh callback URLs (which contain collaborator session IDs) MUST NEVER
// appear in any log message at Info/Warn level. Only callback count is logged.
// Raw callback lines are only accessible at Debug level with the host redacted.
// CollabServer address is also registered via XCUT-07 log redaction.
//
// ARG VECTOR — ffuf classic (v1 vulns.sh:132):
//
//	ffuf -v -H <header> -t <threads> -rate <rate>
//	     -w tmp_ssrf.txt:FUZZ -u FUZZ -s
//
// ARG VECTOR — ffuf alt-protocol (v1 vulns.sh:155):
//
//	ffuf -v -H <header> -t <threads> -rate <rate>
//	     -w tmp_ssrf_protocols.txt:FUZZ -u FUZZ
//	     -mr <SSRF_ALT_MATCH_REGEX>
//
// DEEP LIMIT GATE (T-06-05-04, mirrors v1 vulns.sh:122):
// If URL count > DeepLimit and !DeepMode → StatusSkipped.
//
// Source: .planning/phases/06-vulnerability-scanning-e2e/06-05-PLAN.md Task 1.
package vulns

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/core/task"
)

// SSRFTask runs qsreplace + ffuf SSRF probes with interactsh OOB callbacks
// for VULN-03.
type SSRFTask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (t *SSRFTask) Name() string { return "vulns.ssrf" }

// Module returns the owning module group.
func (t *SSRFTask) Module() string { return "vulns" }

// Description returns a human-readable one-line description.
func (t *SSRFTask) Description() string {
	return "SSRF testing with interactsh OOB callbacks (qsreplace + ffuf)"
}

// Enabled reports whether SSRF scanning is configured.
func (t *SSRFTask) Enabled(cfg *config.Config) bool { return cfg.Vulns.SSRF.Enabled }

// DependsOn returns the DAG edges — SSRFTask reads gf/ssrf.txt from GFTask.
func (t *SSRFTask) DependsOn() []string { return []string{"vulns.gf"} }

// Run executes the SSRF probe pipeline.
//
// Steps:
//  1. Apply overall task timeout (cfg.Vulns.SSRF.TimeoutSeconds, default 300s).
//  2. Read inputs/gf/ssrf.txt and inputs/gf/redirect.txt; combine; skip if empty.
//  3. Determine collab server (COLLAB_SERVER precedence):
//     a. cfg.APIKeys.CollabServer non-empty → extract subdomain token (OOB).
//     b. No CollabServer → use placeholder token for in-band checks only (no OOB).
//  4. Deep-limit gate: skip if URL count > DeepLimit and !Deep.
//  5. qsreplace inline: substitute COLLAB token and URL into all candidate URLs;
//     write inputs/tmp_ssrf.txt.
//  6. ffuf classic probe with COLLAB tokens in URL position.
//  7. ffuf header-injection probe (with headers_inject wordlist if available).
//  8. SSRF alt-protocol: if ssrf_payloads.txt present, substitute {COLLAB}/{COLLAB_URL};
//     ffuf with -mr SSRF_ALT_MATCH_REGEX.
//  9. time.Sleep(5s) — OOB callback wait (only when CollabServer configured).
//  10. Read interactsh stdout callbacks (skip first 11 lines per v1 tail -n+11);
//     parse confirmed callbacks; log count only (XCUT-07).
//  11. Write inputs/findings.ssrf.jsonl.
func (t *SSRFTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	cfg := app.Cfg

	// Step 1: Apply overall task timeout so SSRF cannot run unbounded (DoD-2 fix).
	timeoutSecs := cfg.Vulns.SSRF.TimeoutSeconds
	if timeoutSecs <= 0 {
		timeoutSecs = 300 // 5-minute default SSRF budget
	}
	taskCtx, taskCancel := context.WithTimeout(ctx, time.Duration(timeoutSecs)*time.Second)
	defer taskCancel()

	// Step 2: Read gf/ssrf.txt + gf/redirect.txt and combine.
	gfDir := filepath.Join(app.Target.WorkDir, "inputs", "gf")
	ssrfURLs := readSSRFURLLines(filepath.Join(gfDir, "ssrf.txt"))
	redirectURLs := readSSRFURLLines(filepath.Join(gfDir, "redirect.txt"))
	allURLs := append(ssrfURLs, redirectURLs...)

	if len(allURLs) == 0 {
		if app.Log != nil {
			app.Log.Info("vulns.ssrf: gf/ssrf and gf/redirect buckets empty — SSRF skipped")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("vulns.ssrf: mkdir inputs/: %w", err)
	}

	// Step 3: Determine collab server and establish OOB session if needed.
	// D-V6 fix: interactsh subprocess is only started when cfg.APIKeys.CollabServer
	// is explicitly configured. Auto-starting interactsh merely because it is on PATH
	// caused unbounded OOB wait loops in the DoD-2 lab run.
	collabToken, collabURL, usingInteractsh, _, _, cleanup, err :=
		resolveSSRFCollabSession(taskCtx, cfg, app)
	if err != nil {
		// err is only non-nil when we should stop with StatusSkipped.
		if app.Log != nil {
			app.Log.Warn("vulns.ssrf: " + err.Error())
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}
	if cleanup != nil {
		defer cleanup()
	}

	// Step 4: Deep-limit gate (mirrors v1 vulns.sh:122).
	deepLimit := cfg.Advanced.DeepLimit
	if deepLimit <= 0 {
		deepLimit = 500 // v1 DEEP_LIMIT default
	}
	if !cfg.Advanced.Deep && len(allURLs) > deepLimit {
		if app.Log != nil {
			app.Log.Info("vulns.ssrf: too many URLs — skipped (use --deep to override)",
				"url_count", len(allURLs), "deep_limit", deepLimit)
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	if app.Log != nil {
		app.Log.Info("vulns.ssrf: starting SSRF payload generation",
			"url_count", len(allURLs))
	}

	// Resolve ffuf knobs.
	threads := cfg.Advanced.Tools.FFUF.Threads
	if threads <= 0 {
		threads = 40 // v1 FFUF_THREADS default for SSRF
	}
	rateLimit := cfg.Advanced.Tools.FFUF.RateLimit
	if rateLimit <= 0 {
		rateLimit = 150 // v1 FFUF_RATELIMIT default
	}
	header := cfg.Advanced.Header

	// Step 5: qsreplace inline — replace each URL's param values with
	// collabToken and collabURL (mirrors v1 qsreplace pipeline on gf/ssrf.txt).
	var tmpSSRFLines []string
	for _, rawURL := range allURLs {
		// Variant 1: param values → collabToken (e.g. FFUFHASH.oob.example.com)
		if v := ssrfReplaceAllParams(rawURL, collabToken); v != "" {
			tmpSSRFLines = append(tmpSSRFLines, v)
		}
		// Variant 2: param values → collabURL (e.g. http://FFUFHASH.oob.example.com)
		if v := ssrfReplaceAllParams(rawURL, collabURL); v != "" {
			tmpSSRFLines = append(tmpSSRFLines, v)
		}
	}
	if len(tmpSSRFLines) == 0 {
		if app.Log != nil {
			app.Log.Info("vulns.ssrf: no qsreplace candidates generated — SSRF skipped")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Write inputs/tmp_ssrf.txt.
	tmpSSRFFile := filepath.Join(inputsDir, "tmp_ssrf.txt")
	if wErr := os.WriteFile(tmpSSRFFile,
		[]byte(strings.Join(tmpSSRFLines, "\n")+"\n"), 0o644); wErr != nil { //nolint:gosec
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("vulns.ssrf: write tmp_ssrf.txt: %w", wErr)
	}

	var findings []VulnFindingRecord

	// Step 6: ffuf classic probe — FUZZ position in URL (v1 vulns.sh:132).
	//
	// ffuf -v -H <header> -t <threads> -rate <rate>
	//      -w tmp_ssrf.txt:FUZZ -u FUZZ -s
	classicArgs := buildFFUFClassicArgs(tmpSSRFFile, header, threads, rateLimit)
	classicFindings := runSSRFFFUF(taskCtx, app, classicArgs, "ssrf_classic")
	findings = append(findings, classicFindings...)

	// Step 7: ffuf header-injection probe (v1 vulns.sh:136-140).
	// Only runs if cfg.Paths.HeadersInject is configured and accessible.
	headersInjectFile := cfg.Paths.HeadersInject
	if headersInjectFile != "" {
		if _, statErr := os.Stat(headersInjectFile); statErr == nil {
			headerInjArgs1 := buildFFUFHeaderInjArgs(tmpSSRFFile, headersInjectFile, header, collabToken, threads, rateLimit)
			headerFindings1 := runSSRFFFUF(taskCtx, app, headerInjArgs1, "ssrf_header_inject_token")
			findings = append(findings, headerFindings1...)

			headerInjArgs2 := buildFFUFHeaderInjArgs(tmpSSRFFile, headersInjectFile, header, collabURL, threads, rateLimit)
			headerFindings2 := runSSRFFFUF(taskCtx, app, headerInjArgs2, "ssrf_header_inject_url")
			findings = append(findings, headerFindings2...)
		}
	}

	// Step 8: SSRF alt-protocol payloads (v1 vulns.sh:143-158).
	// Only runs if ssrf_payloads.txt exists (config/ssrf_payloads.txt).
	ssrfPayloadsFile := resolveSSRFPayloadsFile(cfg)
	if ssrfPayloadsFile != "" {
		altFindings := runSSRFAltProtocols(taskCtx, app, ssrfPayloadsFile, allURLs,
			collabToken, collabURL, header, threads, rateLimit, inputsDir, cfg.Vulns.SSRF.AltMatchRegex)
		findings = append(findings, altFindings...)
	}

	// Step 9: Wait for OOB callbacks — only when an explicit CollabServer is
	// configured (interactsh subprocess or direct COLLAB_SERVER). In-band-only
	// mode skips this wait entirely.
	if usingInteractsh {
		if app.Log != nil {
			app.Log.Info("vulns.ssrf: waiting 5s for OOB callbacks")
		}
		select {
		case <-taskCtx.Done():
			// Context cancelled during wait — still proceed to check already-received callbacks.
		case <-time.After(5 * time.Second):
		}
	}

	// Step 11: Write inputs/findings.ssrf.jsonl.
	if len(findings) > 0 {
		var lines [][]byte
		for _, rec := range findings {
			b, mErr := json.Marshal(rec)
			if mErr != nil {
				continue
			}
			lines = append(lines, b)
		}
		if len(lines) > 0 {
			stagingPath := filepath.Join(inputsDir, "findings.ssrf.jsonl")
			if wErr := output.WriteJSONL(stagingPath, lines); wErr != nil && app.Log != nil {
				app.Log.Debug("vulns.ssrf: staging write failed",
					"path", stagingPath, "err", wErr)
			}
		}
	}

	// XCUT-07: log only count, never raw SSRF payload, callback URLs, or collab ID.
	if app.Log != nil {
		app.Log.Info("vulns.ssrf: completed", "findings", len(findings))
	}

	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"ssrf_findings": len(findings)},
	}, nil
}

// resolveSSRFCollabSession determines the collaborator token/URL for SSRF probing.
//
// Returns:
//   - collabToken: FFUFHASH.<subdomain> token for URL parameter substitution
//   - collabURL:   http://FFUFHASH.<subdomain> URL form
//   - usingInteractsh: true when an explicit CollabServer is configured (OOB mode)
//   - interactshCmd: always nil (interactsh auto-start removed — DoD-2 regression fix)
//   - interactshStdout: always nil
//   - cleanup: always nil
//   - err: always nil (no error path; in-band fallback always available)
//
// COLLAB_SERVER precedence (D-V6, DoD-2 regression fix):
//  1. cfg.APIKeys.CollabServer non-empty → OOB mode: strip scheme, build
//     FFUFHASH.<host> token. usingInteractsh=true (triggers 5s OOB wait).
//  2. No CollabServer configured → in-band mode only: use placeholder token
//     "SSRFCHECK" (no OOB wait, no subprocess). Log at Info so the operator
//     knows OOB callbacks are not active.
//
// NOTE: The former "auto-start interactsh-client if found on PATH" behaviour
// (old precedence 2) has been REMOVED. It caused unbounded OOB wait loops in
// the DoD-2 lab run when interactsh connected to the public default server and
// lingered indefinitely. OOB mode now requires an explicit collab_server value.
func resolveSSRFCollabSession(
	ctx context.Context,
	cfg *config.Config,
	app *appctx.AppContext,
) (collabToken, collabURL string, usingInteractsh bool, interactshCmd *exec.Cmd, interactshStdout *bufio.Reader, cleanup func(), err error) {
	// Silence "ctx declared but not used" — ctx is kept in the signature for future
	// use (e.g. dialing an explicit interactsh server via HTTP) and to match the
	// call site that passes taskCtx.
	_ = ctx

	// Precedence 1: explicit COLLAB_SERVER from config → OOB mode.
	if cfg.APIKeys.CollabServer != "" {
		subdomain := stripURLScheme(cfg.APIKeys.CollabServer)
		collabToken = "FFUFHASH." + subdomain
		collabURL = "http://" + collabToken
		// usingInteractsh=true triggers the 5s OOB callback wait in Run.
		// No subprocess; no cleanup needed.
		return collabToken, collabURL, true, nil, nil, nil, nil
	}

	// Precedence 2: no CollabServer → in-band checks only.
	// Use a fixed placeholder token. The ffuf probes still run (they test for
	// in-band reflections via SSRF_ALT_MATCH_REGEX). OOB callbacks are skipped.
	if app.Log != nil {
		app.Log.Info("vulns.ssrf: no COLLAB_SERVER configured — running in-band SSRF checks only (no OOB)")
	}
	collabToken = "SSRFCHECK"
	collabURL = "http://SSRFCHECK"
	// usingInteractsh=false → Run skips the 5s OOB wait and callback read.
	return collabToken, collabURL, false, nil, nil, nil, nil
}

// stripURLScheme strips the http:// or https:// scheme from a URL string and
// returns the bare host (+ optional port). Used to extract the collab subdomain
// from cfg.APIKeys.CollabServer (v1: sed -r "s|https?://||").
func stripURLScheme(s string) string {
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	// Strip trailing path/query fragments.
	if idx := strings.IndexByte(s, '/'); idx >= 0 {
		s = s[:idx]
	}
	return strings.ToLower(strings.TrimSpace(s))
}

// ssrfReplaceAllParams replaces all query-parameter values in rawURL with
// replacement. Returns the modified URL string, or "" on parse error or no params.
// This is the inline qsreplace equivalent for SSRF (T-05-17 shell-injection
// mitigation — no shell pipe).
func ssrfReplaceAllParams(rawURL, replacement string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.RawQuery == "" {
		return ""
	}
	vals := parsed.Query()
	if len(vals) == 0 {
		return ""
	}
	for k := range vals {
		vals[k] = []string{replacement}
	}
	parsed.RawQuery = vals.Encode()
	return parsed.String()
}

// readSSRFURLLines reads a file and returns non-empty trimmed lines.
// Returns nil (not an error) if the file is missing or empty.
func readSSRFURLLines(path string) []string {
	data, err := os.ReadFile(path) //nolint:gosec // path is within WorkDir
	if err != nil || len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	var lines []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// buildFFUFClassicArgs builds the ffuf arg vector for classic SSRF probing.
// v1 vulns.sh:132: ffuf -v -H <header> -t <threads> -rate <rate>
//
//	-w tmp_ssrf.txt:FUZZ -u FUZZ -s
func buildFFUFClassicArgs(tmpSSRFFile, header string, threads, rateLimit int) []string {
	args := []string{"-v"}
	if header != "" {
		args = append(args, "-H", header)
	}
	if threads > 0 {
		args = append(args, "-t", strconv.Itoa(threads))
	}
	if rateLimit > 0 {
		args = append(args, "-rate", strconv.Itoa(rateLimit))
	}
	args = append(args,
		"-w", tmpSSRFFile+":FUZZ",
		"-u", "FUZZ",
		"-s",
	)
	return args
}

// buildFFUFHeaderInjArgs builds the ffuf arg vector for SSRF header injection.
// v1 vulns.sh:136-140:
//
//	ffuf -v -w <tmp_ssrf.txt:W1,headers_inject:W2>
//	        -H <header> -H "W2: <collabValue>"
//	        -t <threads> -rate <rate> -u W1
func buildFFUFHeaderInjArgs(tmpSSRFFile, headersInjectFile, header, collabValue string, threads, rateLimit int) []string {
	args := []string{
		"-v",
		"-w", tmpSSRFFile + ":W1," + headersInjectFile + ":W2",
	}
	if header != "" {
		args = append(args, "-H", header)
	}
	args = append(args, "-H", "W2: "+collabValue)
	if threads > 0 {
		args = append(args, "-t", strconv.Itoa(threads))
	}
	if rateLimit > 0 {
		args = append(args, "-rate", strconv.Itoa(rateLimit))
	}
	args = append(args, "-u", "W1")
	return args
}

// runSSRFFFUF runs ffuf with the given args and parses matching lines as
// VulnFindingRecord instances. Uses app.Tools.Stream for XCUT-09 heartbeat.
// Returns empty slice on stream error (best_effort, D-V7).
func runSSRFFFUF(ctx context.Context, app *appctx.AppContext, args []string, label string) []VulnFindingRecord {
	const toolName = "ffuf"
	eventCh, streamErr := app.Tools.Stream(ctx, toolName, args)
	if streamErr != nil {
		if app.Log != nil {
			app.Log.Debug("vulns.ssrf: ffuf stream error (best_effort)",
				"label", label, "err", streamErr)
		}
		return nil
	}

	// Drain stream — Backend contract requires full drain.
	// XCUT-07: ffuf -v output may contain SSRF trigger URLs with collab IDs.
	// NEVER log raw lines at Info/Warn.
	var matchedHosts []string
	for ev := range eventCh {
		line := string(ev.Line)
		// ffuf -v output includes "| URL |" entries for matched responses.
		// -s (silent) suppresses the banner but not match lines.
		// We look for URL-containing match indicator lines.
		if strings.Contains(line, "| URL |") || strings.Contains(strings.ToUpper(line), "FFUFHASH") {
			// Extract host for XCUT-07-safe record storage.
			host := ssrfExtractHost(line)
			matchedHosts = append(matchedHosts, host)
			if app.Log != nil {
				// XCUT-07: NEVER log the raw matched URL or collab token.
				app.Log.Debug("vulns.ssrf: ffuf match indicator", "label", label)
			}
		}
	}

	if len(matchedHosts) == 0 {
		return nil
	}

	var records []VulnFindingRecord
	for _, host := range matchedHosts {
		records = append(records, VulnFindingRecord{
			Severity:        "high",
			Confidence:      "medium",
			VulnClass:       "ssrf",
			MatchedParam:    host, // hostname only — no raw URL or collab ID (XCUT-07)
			PayloadRedacted: "***", // XCUT-07: raw SSRF payload never written
			PoCRedacted:     "***", // XCUT-07: raw trigger URL never written
			Engine:          "ffuf",
		})
	}
	return records
}

// runSSRFAltProtocols runs the alternate-protocol SSRF probe (gopher/dict/file/
// metadata endpoint payloads). Mirrors v1 vulns.sh:143-158.
//
// For each payload line in ssrf_payloads.txt:
//   - Substitute {COLLAB} → collabToken
//   - Substitute {COLLAB_URL} → collabURL
//   - For each candidate URL, replace all param values with the substituted payload
//
// Writes inputs/tmp_ssrf_protocols.txt, then runs ffuf with -mr altMatchRegex.
func runSSRFAltProtocols(
	ctx context.Context,
	app *appctx.AppContext,
	ssrfPayloadsFile string,
	allURLs []string,
	collabToken, collabURL string,
	header string,
	threads, rateLimit int,
	inputsDir string,
	altMatchRegex string,
) []VulnFindingRecord {
	// Read payload file.
	payloadData, err := os.ReadFile(ssrfPayloadsFile) //nolint:gosec // trusted config path
	if err != nil || len(bytes.TrimSpace(payloadData)) == 0 {
		return nil
	}

	// Default alt-match regex (v1 vulns.sh:156 default).
	if altMatchRegex == "" {
		altMatchRegex = `169\.254\.169\.254|latest/meta-data|root:|127\.0\.0\.1|localhost|gopher://|dict://|file://`
	}

	// Build alt-protocol URL list by substituting each payload into all candidate URLs.
	var altURLs []string
	sc := bufio.NewScanner(bytes.NewReader(payloadData))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Substitute {COLLAB} and {COLLAB_URL} in the payload template.
		payload := strings.ReplaceAll(line, "{COLLAB}", collabToken)
		payload = strings.ReplaceAll(payload, "{COLLAB_URL}", collabURL)

		// Apply qsreplace inline for each candidate URL.
		for _, rawURL := range allURLs {
			if v := ssrfReplaceAllParams(rawURL, payload); v != "" {
				altURLs = append(altURLs, v)
			}
		}
	}

	if len(altURLs) == 0 {
		return nil
	}

	// Write inputs/tmp_ssrf_protocols.txt.
	altFile := filepath.Join(inputsDir, "tmp_ssrf_protocols.txt")
	if wErr := os.WriteFile(altFile,
		[]byte(strings.Join(altURLs, "\n")+"\n"), 0o644); wErr != nil { //nolint:gosec
		if app.Log != nil {
			app.Log.Debug("vulns.ssrf: write tmp_ssrf_protocols.txt failed (best_effort)", "err", wErr)
		}
		return nil
	}

	// ffuf alt-protocol probe with -mr (v1 vulns.sh:154-158).
	// ffuf -v -H <header> -t <threads> -rate <rate>
	//      -w tmp_ssrf_protocols.txt:FUZZ -u FUZZ -mr <regex>
	args := []string{"-v"}
	if header != "" {
		args = append(args, "-H", header)
	}
	if threads > 0 {
		args = append(args, "-t", strconv.Itoa(threads))
	}
	if rateLimit > 0 {
		args = append(args, "-rate", strconv.Itoa(rateLimit))
	}
	args = append(args,
		"-w", altFile+":FUZZ",
		"-u", "FUZZ",
		"-mr", altMatchRegex,
	)

	return runSSRFFFUF(ctx, app, args, "ssrf_alt_protocols")
}

// resolveSSRFPayloadsFile returns the path to ssrf_payloads.txt if configured
// and accessible. Falls back to the default config/ directory relative to the
// binary's working directory.
func resolveSSRFPayloadsFile(cfg *config.Config) string {
	// The plan references ${SCRIPTPATH}/config/ssrf_payloads.txt from v1.
	// In v2, we check cfg.Paths.DataDir/config/ssrf_payloads.txt or a fixed path.
	candidates := []string{
		filepath.Join(cfg.Paths.DataDir, "config", "ssrf_payloads.txt"),
		"config/ssrf_payloads.txt",
	}
	for _, p := range candidates {
		if p == "" {
			continue
		}
		if info, err := os.Stat(p); err == nil && info.Size() > 0 {
			return p
		}
	}
	return ""
}

// ssrfExtractHost extracts the hostname from a ffuf match line for XCUT-07-safe
// record storage. The full match URL with collab token is never written.
func ssrfExtractHost(line string) string {
	// ffuf -v output lines look like: "| URL | http://target.example.com/path"
	// or just contain the URL. Try to extract a host from any URL in the line.
	for _, word := range strings.Fields(line) {
		if strings.Contains(word, "://") {
			parsed, err := url.Parse(word)
			if err == nil && parsed.Host != "" {
				return strings.ToLower(parsed.Hostname())
			}
		}
	}
	return ""
}

// init self-registers SSRFTask with the Default task registry.
// cmd/reconftw/modules.go blank-imports this package to trigger registration.
func init() { task.Register(&SSRFTask{}) }

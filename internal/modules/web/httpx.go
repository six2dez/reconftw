// httpx.go — HTTPXTask: HTTP probe (httpx), DAG root for the web pipeline.
//
// HTTPXTask is the dependency root — DependsOn returns nil. All other web
// Tasks DependsOn "web.httpx" (directly or transitively). The entire web
// pipeline is best_effort (D-W12); httpx is NOT fail_fast.
//
// INPUT BOUNDARY (D-W10):
//  1. ctx value keyed by hostsFileKey — set by runWebCmd via CtxWithHostsFile
//  2. artefacts/hosts.jsonl (prior web run output)
//  3. artefacts/subdomains.jsonl (prior subs run; host field extracted)
//  4. fail-fast with "no host list: run `subs` first or pass --hosts <file>"
//
// OUTPUT SCHEMA (D-W11 hosts.jsonl):
//
//	{host, url, scheme, port, status, title, tech[], content_length, ip, cdn}
//
// The cdn field is populated empty here; cdncheck Task (Phase 5 plan-03) fills it.
//
// ARG VECTOR (RESEARCH §httpx — verbatim v1 form; [ASSUMED] flags noted):
//
//	httpx -follow-host-redirects -random-agent -status-code
//	      -p <ports> -threads <n> -rl <n> -timeout <n>
//	      -silent -retries 2 -title -web-server -tech-detect
//	      -location -no-color -json -o <output-file>
//	      -l <input-file>
//
// [ASSUMED: -follow-host-redirects is the correct v1 flag form; verify at install.]
//
// Source: .planning/phases/05-web-pipeline-e2e/05-01-PLAN.md Task 2.
package web

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5" //nolint:gosec // used for input-file hash only, not crypto
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

// hostsFileKey is the context key type for the --hosts flag value.
// Using a private unexported type prevents key collisions from other packages.
type hostsFileKey struct{}

// CtxWithHostsFile returns a new context carrying the --hosts flag value.
// Called by runWebCmd before executing the web pipeline.
func CtxWithHostsFile(ctx context.Context, hostsFile string) context.Context {
	return context.WithValue(ctx, hostsFileKey{}, hostsFile)
}

// hostsFileFromCtx extracts the --hosts flag value from a context.
// Returns "" if not set.
func hostsFileFromCtx(ctx context.Context) string {
	if v, ok := ctx.Value(hostsFileKey{}).(string); ok {
		return v
	}
	return ""
}

// HostRecord is the D-W11 JSONL schema for artefacts/hosts.jsonl.
// Written by HTTPXTask.Run after parsing httpx's JSONL output.
type HostRecord struct {
	Host          string   `json:"host"`
	URL           string   `json:"url"`
	Scheme        string   `json:"scheme"`
	Port          string   `json:"port"`
	Status        int      `json:"status"`
	Title         string   `json:"title"`
	Tech          []string `json:"tech"`
	ContentLength int      `json:"content_length"`
	IP            string   `json:"ip"`
	CDN           string   `json:"cdn"` // populated by cdncheck Task later
}

// httpxRaw is the subset of httpx JSONL fields we parse.
// httpx outputs more fields; we only map the ones in D-W11.
type httpxRaw struct {
	Input         string   `json:"input"`
	URL           string   `json:"url"`
	Scheme        string   `json:"scheme"`
	Port          int      `json:"port"`
	StatusCode    int      `json:"status-code"`
	Title         string   `json:"title"`
	Technologies  []string `json:"tech"`
	ContentLength int      `json:"content-length"`
	Host          string   `json:"host"`
	A             []string `json:"a"` // resolved IPs from httpx
}

// HTTPXTask runs httpx HTTP probe and writes hosts.jsonl.
type HTTPXTask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (t *HTTPXTask) Name() string { return "web.httpx" }

// Module returns the owning module group.
func (t *HTTPXTask) Module() string { return "web" }

// Description returns a human-readable one-line description.
func (t *HTTPXTask) Description() string { return "HTTP probe (httpx)" }

// Enabled reports whether this task should run.
// Maps to cfg.Web.Probe.Enabled (WEBPROBEFULL legacy alias).
func (t *HTTPXTask) Enabled(cfg *config.Config) bool {
	return cfg.Web.Probe.Enabled
}

// DependsOn returns nil — HTTPXTask IS the DAG root (D-W12).
func (t *HTTPXTask) DependsOn() []string { return nil }

// Run executes httpx and writes parsed records to artefacts/hosts.jsonl.
//
// Input resolution follows D-W10 precedence:
//  1. ctx-carried --hosts FILE (set via CtxWithHostsFile by runWebCmd)
//  2. artefacts/hosts.jsonl — prior web run
//  3. artefacts/subdomains.jsonl — prior subs run (extracts host fields)
//  4. fail-fast error
func (t *HTTPXTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "httpx"
	cfg := app.Cfg

	// Step 1: Resolve input file (D-W10 precedence).
	inputFile, err := resolveHostInput(ctx, app)
	if err != nil {
		return task.Result{Status: task.StatusErrored}, err
	}

	// Validate --hosts path against path traversal (T-05-01).
	if err := validateHostsPath(inputFile); err != nil {
		return task.Result{Status: task.StatusErrored}, err
	}

	// Compute input hash for checkpoint idempotency (informational).
	inputHash, _ := fileHash(inputFile)

	// Step 2: Build output file path.
	artefactsDir := filepath.Join(app.Target.WorkDir, "artefacts")
	if err := os.MkdirAll(artefactsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.httpx: mkdir artefacts/: %w", err)
	}
	outputFile := filepath.Join(artefactsDir, "hosts.jsonl")

	// Step 3: Build arg vector (RESEARCH §httpx verbatim v1 form).
	// Ports: cfg.Web.Probe.Ports; "" → omit -p flag (httpx uses its default).
	// Threads: cfg.Web.Probe.Threads; 0 → omit.
	// RateLimit: cfg.Web.Probe.RateLimit; 0 → omit.
	// Timeout: cfg.Web.Probe.TimeoutSeconds; 0 → omit.
	args := []string{
		"-follow-host-redirects", // [ASSUMED: verify exact flag at install — DoD-1]
		"-random-agent",
		"-status-code",
	}
	if ports := cfg.Web.Probe.Ports; ports != "" {
		args = append(args, "-p", ports)
	}
	if threads := cfg.Web.Probe.Threads; threads > 0 {
		args = append(args, "-threads", strconv.Itoa(threads))
	}
	if rl := cfg.Web.Probe.RateLimit; rl > 0 {
		args = append(args, "-rl", strconv.Itoa(rl))
	}
	if to := cfg.Web.Probe.TimeoutSeconds; to > 0 {
		args = append(args, "-timeout", strconv.Itoa(to))
	}
	args = append(args,
		"-silent",
		"-retries", "2",
		"-title",
		"-web-server",
		"-tech-detect",
		"-location",
		"-no-color",
		"-json",
		"-o", outputFile,
		"-l", inputFile,
	)

	// Step 4: Execute httpx.
	// T-05-02: stdout routed to run.log only (GAP-3 pattern via app.Tools).
	res, err := app.Tools.Run(ctx, toolName, args)
	if err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.httpx: tool execution failed: %w", err)
	}

	// Step 5: Parse JSONL output.
	// httpx writes results to -o file; fall back to res.Stdout.
	var jsonlSrc []byte
	if data, rerr := os.ReadFile(outputFile); rerr == nil && len(data) > 0 { //nolint:gosec
		jsonlSrc = data
	} else if len(res.Stdout) > 0 {
		jsonlSrc = res.Stdout
	}

	records, parseErr := parseHTTPXOutput(jsonlSrc)
	if parseErr != nil && app.Log != nil {
		app.Log.Debug("web.httpx: parse warnings", "err", parseErr)
	}

	// Step 6: Scope-filter and append to artefacts/hosts.jsonl via app.Tree.
	var inScope [][]byte
	for _, rec := range records {
		hostVal := rec.Host
		if hostVal == "" {
			hostVal = rec.URL
		}
		if app.Tree != nil && !app.Tree.InScope(hostVal) {
			continue
		}
		line, merr := json.Marshal(rec)
		if merr != nil {
			continue
		}
		inScope = append(inScope, line)
	}

	if len(inScope) > 0 {
		if appendErr := app.Tree.Append("hosts", inScope); appendErr != nil {
			if app.Log != nil {
				app.Log.Debug("web.httpx: Tree.Append failed",
					"records", len(inScope), "err", appendErr)
			}
			// Non-fatal per best_effort (D-W12).
		}
	}

	if app.Log != nil && inputHash != "" {
		app.Log.Debug("web.httpx: completed",
			"input", inputFile,
			"input_hash", inputHash,
			"records", len(inScope))
	}

	return task.Result{
		Status:  task.StatusDone,
		Outputs: []string{outputFile},
		Stats:   map[string]int{"hosts_found": len(inScope)},
	}, nil
}

// resolveHostInput implements the D-W10 input precedence.
func resolveHostInput(ctx context.Context, app *appctx.AppContext) (string, error) {
	// Priority 1: ctx-carried --hosts flag (set by runWebCmd).
	if hostsFile := hostsFileFromCtx(ctx); hostsFile != "" {
		if _, err := os.Stat(hostsFile); err == nil {
			return hostsFile, nil
		}
	}

	// Priority 2: prior artefacts/hosts.jsonl.
	hostsJSONL := filepath.Join(app.Target.WorkDir, "artefacts", "hosts.jsonl")
	if info, err := os.Stat(hostsJSONL); err == nil && info.Size() > 0 {
		return hostsJSONL, nil
	}

	// Priority 3: derive hosts from artefacts/subdomains.jsonl.
	subdomainsJSONL := filepath.Join(app.Target.WorkDir, "artefacts", "subdomains.jsonl")
	if _, err := os.Stat(subdomainsJSONL); err == nil {
		hostsFromSubs, err := extractHostsFromSubdomainsJSONL(subdomainsJSONL, app)
		if err == nil && hostsFromSubs != "" {
			return hostsFromSubs, nil
		}
	}

	return "", fmt.Errorf("web.httpx: no host list: run `subs` first or pass --hosts <file>")
}

// extractHostsFromSubdomainsJSONL reads artefacts/subdomains.jsonl and
// writes a plain-text hostname file to inputs/httpx.hosts.txt, returning
// its path. Returns error if subdomains.jsonl is empty or unreadable.
func extractHostsFromSubdomainsJSONL(subdomainsPath string, app *appctx.AppContext) (string, error) {
	f, err := os.Open(subdomainsPath) //nolint:gosec // path from trusted WorkDir
	if err != nil {
		return "", fmt.Errorf("open subdomains.jsonl: %w", err)
	}
	defer f.Close() //nolint:errcheck

	var hostnames []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec struct {
			Subdomain string `json:"subdomain"`
			Host      string `json:"host"`
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}
		h := rec.Subdomain
		if h == "" {
			h = rec.Host
		}
		if h != "" {
			hostnames = append(hostnames, h)
		}
	}
	if len(hostnames) == 0 {
		return "", fmt.Errorf("subdomains.jsonl: no hostnames found")
	}

	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return "", fmt.Errorf("mkdir inputs/: %w", err)
	}
	hostsPath := filepath.Join(inputsDir, "httpx.hosts.txt")
	content := strings.Join(hostnames, "\n") + "\n"
	if err := os.WriteFile(hostsPath, []byte(content), 0o644); err != nil { //nolint:gosec
		return "", fmt.Errorf("write httpx.hosts.txt: %w", err)
	}
	return hostsPath, nil
}

// validateHostsPath guards against path traversal in --hosts values (T-05-01).
func validateHostsPath(path string) error {
	// Reject paths containing ".." traversal sequences.
	if strings.Contains(filepath.Clean(path), "..") {
		return fmt.Errorf("web.httpx: --hosts path contains path traversal: %q", path)
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("web.httpx: --hosts file not accessible %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("web.httpx: --hosts path is not a regular file: %q", path)
	}
	return nil
}

// fileHash computes a hex-encoded MD5 hash of the file at path.
// Used only for checkpoint input-hash tracking (not cryptographic security).
func fileHash(path string) (string, error) {
	data, err := os.ReadFile(path) //nolint:gosec // caller already validated
	if err != nil {
		return "", err
	}
	h := md5.Sum(data) //nolint:gosec // MD5 for tracking only, not security
	return hex.EncodeToString(h[:]), nil
}

// parseHTTPXOutput parses httpx JSONL output into HostRecord slice.
// Lines that fail to parse are silently skipped (passive parsing).
// Returns records and a non-nil error only when ALL lines failed to parse.
func parseHTTPXOutput(jsonlData []byte) ([]HostRecord, error) {
	if len(jsonlData) == 0 {
		return nil, nil
	}

	var records []HostRecord
	var parseErrors int
	scanner := bufio.NewScanner(bytes.NewReader(jsonlData))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var raw httpxRaw
		if err := json.Unmarshal(line, &raw); err != nil {
			parseErrors++
			continue
		}

		// Map httpx raw fields to D-W11 HostRecord schema.
		host := raw.Host
		if host == "" {
			host = raw.Input
		}

		// First resolved IP from httpx "a" field (DNS A records).
		ip := ""
		if len(raw.A) > 0 {
			ip = raw.A[0]
		}

		// Port as string (D-W11 uses string for scheme flexibility).
		portStr := ""
		if raw.Port > 0 {
			portStr = strconv.Itoa(raw.Port)
		}

		rec := HostRecord{
			Host:          host,
			URL:           raw.URL,
			Scheme:        raw.Scheme,
			Port:          portStr,
			Status:        raw.StatusCode,
			Title:         raw.Title,
			Tech:          raw.Technologies,
			ContentLength: raw.ContentLength,
			IP:            ip,
			CDN:           "", // populated by cdncheck Task (Phase 5 plan-03)
		}
		if rec.Tech == nil {
			rec.Tech = []string{}
		}
		records = append(records, rec)
	}

	if parseErrors > 0 && len(records) == 0 {
		return nil, fmt.Errorf("web.httpx: all %d lines failed to parse", parseErrors)
	}
	return records, nil
}

// init self-registers HTTPXTask with the Default task registry.
// cmd/reconftw/modules.go blank-imports this package to trigger registration.
func init() { task.Register(&HTTPXTask{}) }

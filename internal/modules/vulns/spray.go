// spray.go — SprayTask: password spraying (brutespray default / brutus deep-gated).
//
// SprayTask closes the PAR-02 gap: cfg.Vulns.Spray{Enabled:true,
// Engine:"brutespray", DeepOnly:true} (defaults.go:216) was ORPHANED — read by
// zero tasks, and brutespray (tools.lock) was never invoked. This task ports
// bash spraying() (modules/vulns.sh:615-691):
//
//	brutespray -f hosts/portscan_active.gnmap -T <concurrence> -o vulns/brutespray
//	brutus     --json -o vulns/brutus.jsonl  < hosts/service_fingerprints.jsonl
//
// GATING (bash parity — vulns.sh:622-624 + SPRAY_BRUTUS_ONLY_DEEP):
//   - target is an IP literal            → StatusSkipped
//   - hosts/portscan_active.gnmap absent → StatusSkipped (no-input)
//   - cfg.Vulns.Spray.DeepOnly && !Deep  → StatusSkipped (deep-gated)
//   - engine "brutus" additionally requires DeepMode (bash SPRAY_BRUTUS_ONLY_DEEP
//     default true) — brutus never sprays outside --deep.
//
// INPUT: hosts/portscan_active.gnmap + hosts/service_fingerprints.jsonl are
// produced by the web portscan stage (13-03). SprayTask reads them directly
// (DependsOn nil) because web runs before vulns in ModeAll/ModeDeep; the "vulns.spray"
// prefix is wired into the vulns stage list by 13-08. vulns runs only in
// ModeAll/ModeDeep — never in recon.
//
// BRUTUS STDIN SEAM (FOUND-10 allowlisted, mirrors reverseip.go / github_repos.go):
// brutus reads the service-fingerprint JSON on STDIN (bash: `brutus ... <input`).
// The name-keyed Backend/Runner (app.Tools) has no stdin seam, so brutus is
// invoked through the brutusRunner package var (direct, timeout-bounded
// exec.CommandContext with cmd.Stdin). brutespray takes a `-f <file>` argument
// and therefore routes through app.Tools.Run normally.
//
// XCUT-07 (T-13-07-03) — SPRAYED CREDENTIALS ARE NEVER PERSISTED:
// Discovered credentials MUST NOT be written to the JSONL findings. Only the
// host / service / port that accepted a weak credential is recorded; the
// user:password (or key) is redacted to "***" (PayloadRedacted/PoCRedacted).
// brutus credential wordlists cross to the tool as FILE PATHS (-u/-p/-k), never
// as raw values on argv.
//
// FAILURE POLICY (best_effort, D-V7): a missing brutespray/brutus or a tool
// error logs a warning and returns StatusSkipped/StatusDone — never
// StatusErrored, so spraying never aborts the vulns pipeline.
//
// Source: .planning/phases/13-domain-parity/13-07-PLAN.md Task 1.
package vulns

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/log"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/core/task"
)

// brutusTimeout bounds a single brutus spraying invocation. Spraying can be
// long-running; the timeout is generous but prevents an unbounded hang.
const brutusTimeout = 30 * time.Minute

// errBrutusNotInstalled is the sentinel returned by brutusRunner when the
// brutus binary is not resolvable on PATH (D-V7 graceful skip).
var errBrutusNotInstalled = errors.New("brutus not installed")

// brutusRunner runs brutus with the service-fingerprint JSON at serviceFPPath
// piped on STDIN (bash: `brutus ... <input`) and the given argv. Overridable in
// tests. Returns errBrutusNotInstalled when the binary is absent so a missing
// optional tool degrades to StatusSkipped instead of failing the pipeline.
//
// Direct exec.CommandContext (FOUND-10 allowlisted) is required because the
// name-keyed Backend/Runner does not support stdin injection — identical to the
// hakip2host (reverseip.go) and git-clone (github_repos.go) seams.
var brutusRunner = func(ctx context.Context, serviceFPPath string, args []string) error {
	bin, err := exec.LookPath("brutus")
	if err != nil {
		return errBrutusNotInstalled // not installed — graceful skip
	}
	cmdCtx, cancel := context.WithTimeout(ctx, brutusTimeout)
	defer cancel()

	f, err := os.Open(serviceFPPath) //nolint:gosec // path is within WorkDir
	if err != nil {
		return fmt.Errorf("open service-fingerprint input: %w", err)
	}
	defer f.Close() //nolint:errcheck

	//nolint:gosec // bin resolved via LookPath; args are tool-controlled; creds
	// cross as file paths (-u/-p/-k), never raw values (XCUT-07).
	cmd := exec.CommandContext(cmdCtx, bin, args...)
	cmd.Stdin = f
	return cmd.Run()
}

// SprayTask runs password spraying (brutespray default, brutus deep-gated)
// against the active portscan gnmap for PAR-02.
type SprayTask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (t *SprayTask) Name() string { return "vulns.spray" }

// Module returns the owning module group.
func (t *SprayTask) Module() string { return "vulns" }

// Description returns a human-readable one-line description.
func (t *SprayTask) Description() string {
	return "Password spraying (brutespray default / brutus deep-gated) from the active portscan gnmap"
}

// Enabled reports whether password spraying is configured (reads the
// previously-orphaned cfg.Vulns.Spray.Enabled).
func (t *SprayTask) Enabled(cfg *config.Config) bool { return cfg.Vulns.Spray.Enabled }

// DependsOn returns nil — SprayTask reads workspace files (hosts/portscan_active.gnmap,
// hosts/service_fingerprints.jsonl) written by the web portscan stage, which runs
// before vulns in ModeAll/ModeDeep. It is not part of the gf-bucket DAG.
func (t *SprayTask) DependsOn() []string { return nil }

// Run executes the password-spraying pipeline (bash spraying(), vulns.sh:615-691).
//
// Steps:
//  1. Gate: skip if target is an IP literal (bash `! domain =~ IP`).
//  2. Gate: skip if hosts/portscan_active.gnmap is absent/empty (no-input).
//  3. Gate: skip if cfg.Vulns.Spray.DeepOnly && !cfg.Advanced.Deep (deep-gated).
//  4. Engine dispatch:
//     - "brutus": deep-gated; resolve service-fingerprint input → brutus (stdin).
//     - default ("brutespray"): brutespray -f <gnmap> -T <concurrence> -o <dir>.
//  5. Parse credential hits → REDACTED VulnFindingRecords → inputs/findings.spray.jsonl.
func (t *SprayTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	cfg := app.Cfg

	// Step 1: IP-literal target → skip (bash vulns.sh:623 `! domain =~ ^IP$`).
	if app.Target != nil && app.Target.IsIP {
		if app.Log != nil {
			app.Log.Info("vulns.spray: target is an IP literal — spraying skipped (bash parity)")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Step 2: active portscan gnmap must exist and be non-empty (bash vulns.sh:623).
	gnmapPath := filepath.Join(app.Target.WorkDir, "hosts", "portscan_active.gnmap")
	if !sprayFileNonEmpty(gnmapPath) {
		if app.Log != nil {
			app.Log.Info("vulns.spray: hosts/portscan_active.gnmap absent/empty — spraying skipped (run web portscan first)",
				"gnmap", gnmapPath)
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Step 3: deep-gate (cfg.Vulns.Spray.DeepOnly default true).
	if cfg.Vulns.Spray.DeepOnly && !cfg.Advanced.Deep {
		if app.Log != nil {
			app.Log.Info("vulns.spray: DEEP-gated — spraying skipped (use --deep or set spray.deep_only=false)")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Ensure vulns/ output dir exists.
	vulnsDir := filepath.Join(app.Target.WorkDir, "vulns")
	if err := os.MkdirAll(vulnsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("vulns.spray: mkdir vulns/: %w", err)
	}

	// Step 4: engine dispatch (cfg.Vulns.Spray.Engine, default "brutespray").
	engine := strings.ToLower(strings.TrimSpace(cfg.Vulns.Spray.Engine))
	if engine == "brutus" {
		return t.runBrutus(ctx, app, vulnsDir)
	}
	return t.runBrutespray(ctx, app, gnmapPath, vulnsDir)
}

// runBrutespray invokes brutespray over the portscan gnmap (bash vulns.sh:687):
//
//	brutespray -f <gnmap> -T <concurrence> -o vulns/brutespray
//
// brutespray takes the gnmap as a file argument, so it routes through
// app.Tools.Run. A missing/failing brutespray degrades to StatusSkipped.
func (t *SprayTask) runBrutespray(
	ctx context.Context, app *appctx.AppContext, gnmapPath, vulnsDir string,
) (task.Result, error) {
	const toolName = "brutespray"

	concurrence := app.Cfg.Advanced.Tools.Brutespray.Concurrence
	if concurrence <= 0 {
		// bash default: BRUTESPRAY_CONCURRENCE=$((AVAILABLE_CORES * 2)).
		concurrence = runtime.NumCPU() * 2
		if concurrence <= 0 {
			concurrence = 2
		}
	}

	outDir := filepath.Join(vulnsDir, "brutespray")
	args := []string{
		"-f", gnmapPath,
		"-T", strconv.Itoa(concurrence),
		"-o", outDir,
	}

	res, err := app.Tools.Run(ctx, toolName, args)
	if err != nil {
		// best_effort (D-V7): missing/failing brutespray never aborts vulns.
		if app.Log != nil {
			app.Log.Warn("vulns.spray: brutespray unavailable or failed — spraying skipped (best_effort)",
				"error", err.Error())
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Parse success lines from stdout (brutespray prints "[+] ... Login Successful ...").
	// XCUT-07: only host/service/port is recorded; the credential is redacted.
	var stdout []byte
	if res != nil {
		stdout = res.Stdout
	}

	// WR-13-03: confine brutespray's raw output (native files under outDir + the
	// user:pass on stdout success lines) to owner-only perms and register every
	// discovered credential with the log Redactor (L2) BEFORE any log line. The
	// findings stream still carries only "***" (parseBrutesprayHits redacts).
	sprayHardenDir(app.Log, outDir)
	sprayRegisterBrutesprayCreds(app.Log, stdout)

	findings := sprayResolveScopeHosts(app, parseBrutesprayHits(stdout))

	sprayWriteFindings(app, findings)

	if app.Log != nil {
		// XCUT-07: log only the count, never the discovered credential.
		app.Log.Info("vulns.spray: brutespray completed", "credential_findings", len(findings))
	}
	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"spray_findings": len(findings)},
	}, nil
}

// runBrutus invokes brutus with the service-fingerprint JSON on stdin (bash
// vulns.sh:631-673). brutus is DEEP-gated independent of Spray.DeepOnly (bash
// SPRAY_BRUTUS_ONLY_DEEP default true) — it never sprays outside --deep.
//
//	brutus --json -o vulns/brutus.jsonl [-u users][-p passwords][-k keyfile] < service_fp.jsonl
func (t *SprayTask) runBrutus(
	ctx context.Context, app *appctx.AppContext, vulnsDir string,
) (task.Result, error) {
	// brutus deep-gate (bash SPRAY_BRUTUS_ONLY_DEEP default true).
	if !app.Cfg.Advanced.Deep {
		if app.Log != nil {
			app.Log.Info("vulns.spray: brutus is DEEP-gated — spraying skipped (use --deep)")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Resolve the service-fingerprint input: prefer the 13-03 artefact; else
	// generate it from naabu_open.txt via nerva if present (bash vulns.sh:641-647).
	serviceFP := t.resolveServiceFingerprintInput(ctx, app)
	if serviceFP == "" {
		if app.Log != nil {
			app.Log.Info("vulns.spray: no service-fingerprint input for brutus — spraying skipped " +
				"(run web portscan with service_fingerprint=true)")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	outPath := filepath.Join(vulnsDir, "brutus.jsonl")
	args := []string{"--json", "-o", outPath}
	// Credential wordlists cross as FILE PATHS only (XCUT-07 — never raw values).
	if u := strings.TrimSpace(app.Cfg.Advanced.Tools.Brutus.Usernames); u != "" {
		args = append(args, "-u", u)
	}
	if p := strings.TrimSpace(app.Cfg.Advanced.Tools.Brutus.Passwords); p != "" {
		args = append(args, "-p", p)
	}
	if k := strings.TrimSpace(app.Cfg.Advanced.Tools.Brutus.KeyFile); k != "" {
		args = append(args, "-k", k)
	}

	err := brutusRunner(ctx, serviceFP, args)
	if err != nil {
		// best_effort (D-V7): missing/failing brutus never aborts vulns.
		if errors.Is(err, errBrutusNotInstalled) {
			if app.Log != nil {
				app.Log.Warn("vulns.spray: brutus not found in PATH — spraying skipped (best_effort)")
			}
		} else if app.Log != nil {
			app.Log.Warn("vulns.spray: brutus failed — continuing (best_effort)", "error", err.Error())
		}
		// A brutus error may still have produced partial output — try to parse it.
	}

	// WR-13-03: brutus wrote raw --json hits (live user:pass) to outPath at
	// tool-native perms (0644). Confine it to 0600 and register every discovered
	// credential with the log Redactor (L2) BEFORE any log line — mirrors
	// emails.go/github_repos.go. The findings stream still carries only "***".
	sprayHardenFile(app.Log, outPath)
	sprayRegisterBrutusCreds(app.Log, outPath)

	// Parse brutus JSONL output; XCUT-07: only host/service/port recorded, creds redacted.
	findings := sprayResolveScopeHosts(app, parseBrutusHits(outPath))
	sprayWriteFindings(app, findings)

	if app.Log != nil {
		// XCUT-07: log only the count, never the discovered credential.
		app.Log.Info("vulns.spray: brutus completed", "credential_findings", len(findings))
	}
	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"spray_findings": len(findings)},
	}, nil
}

// resolveServiceFingerprintInput returns the path to a service-fingerprint JSONL
// suitable for brutus stdin. Preference (bash vulns.sh:641-647):
//  1. hosts/service_fingerprints.jsonl (from 13-03 nerva step) if non-empty.
//  2. Generate from hosts/naabu_open.txt via nerva (if naabu output + nerva present).
//
// Returns "" when no input can be resolved (caller → StatusSkipped).
func (t *SprayTask) resolveServiceFingerprintInput(ctx context.Context, app *appctx.AppContext) string {
	primary := filepath.Join(app.Target.WorkDir, "hosts", "service_fingerprints.jsonl")
	if sprayFileNonEmpty(primary) {
		return primary
	}

	naabu := filepath.Join(app.Target.WorkDir, "hosts", "naabu_open.txt")
	if !sprayFileNonEmpty(naabu) {
		return ""
	}

	// Generate service fingerprints via nerva (routes through app.Tools — no stdin).
	tmpDir := filepath.Join(app.Target.WorkDir, ".tmp")
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return ""
	}
	genPath := filepath.Join(tmpDir, "service_fp_for_brutus.jsonl")
	nervaArgs := []string{"--json", "-l", naabu, "-o", genPath}
	if _, err := app.Tools.Run(ctx, "nerva", nervaArgs); err != nil {
		if app.Log != nil {
			app.Log.Debug("vulns.spray: nerva service-fingerprint generation failed (best_effort)",
				"error", err.Error())
		}
		return ""
	}
	if sprayFileNonEmpty(genPath) {
		return genPath
	}
	return ""
}

// sprayWriteFindings writes redacted credential findings to the vulns staging
// file inputs/findings.spray.jsonl (consumed by MergeAllVulnsArtefacts). No-op
// when there are no findings.
func sprayWriteFindings(app *appctx.AppContext, findings []VulnFindingRecord) {
	if len(findings) == 0 {
		return
	}
	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		if app.Log != nil {
			app.Log.Debug("vulns.spray: mkdir inputs/ failed (best_effort)", "error", err.Error())
		}
		return
	}
	var lines [][]byte
	for _, rec := range findings {
		b, mErr := json.Marshal(rec)
		if mErr != nil {
			continue
		}
		lines = append(lines, b)
	}
	if len(lines) == 0 {
		return
	}
	stagingPath := filepath.Join(inputsDir, "findings.spray.jsonl")
	if wErr := output.WriteJSONL(stagingPath, lines); wErr != nil && app.Log != nil {
		app.Log.Debug("vulns.spray: staging write failed", "path", stagingPath, "err", wErr)
	}
}

// sprayHardenFile restricts a spray tool's raw hit file (which can contain live
// user:pass) to owner-only 0600 so it is not world-readable (WR-13-03).
// Best-effort: a missing file or chmod failure is logged at Debug, never fatal.
func sprayHardenFile(logger *slog.Logger, path string) {
	if path == "" {
		return
	}
	if err := os.Chmod(path, 0o600); err != nil && !os.IsNotExist(err) && logger != nil {
		logger.Debug("vulns.spray: could not restrict spray output perms", "path", path, "err", err.Error())
	}
}

// sprayHardenDir restricts every file under dir to 0600 and every directory to
// 0700 (WR-13-03) — brutespray writes native output there that can carry live
// credentials. Best-effort; unreadable entries are skipped.
func sprayHardenDir(logger *slog.Logger, dir string) {
	if dir == "" {
		return
	}
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil // best-effort: skip entries we cannot stat
		}
		mode := os.FileMode(0o600)
		if d.IsDir() {
			mode = 0o700
		}
		if err := os.Chmod(p, mode); err != nil && logger != nil {
			logger.Debug("vulns.spray: could not restrict spray output perms", "path", p, "err", err.Error())
		}
		return nil
	})
}

// sprayRegisterBrutusCreds reads brutus's raw --json hit file and registers every
// discovered credential (username/password/key) with the log Redactor (L2) so a
// later log line echoing it is scrubbed (WR-13-03). Values are read transiently
// and NEVER copied into a finding (XCUT-07 — findings carry "***").
func sprayRegisterBrutusCreds(logger *slog.Logger, outPath string) {
	if logger == nil {
		return
	}
	data, err := os.ReadFile(outPath) //nolint:gosec // path within WorkDir
	if err != nil || len(bytes.TrimSpace(data)) == 0 {
		return
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var creds struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Key      string `json:"key"`
		}
		if json.Unmarshal(line, &creds) != nil {
			continue
		}
		for _, v := range []string{creds.Username, creds.Password, creds.Key} {
			if s := strings.TrimSpace(v); s != "" {
				log.RegisterHandlerSecret(logger, s)
			}
		}
	}
}

// sprayRegisterBrutesprayCreds extracts the trailing user:pass from each
// brutespray success line and registers it with the log Redactor (L2) so a later
// log line echoing it is scrubbed (WR-13-03). The credential is NEVER copied into
// a finding (XCUT-07 — parseBrutesprayHits redacts to "***").
func sprayRegisterBrutesprayCreds(logger *slog.Logger, stdout []byte) {
	if logger == nil || len(bytes.TrimSpace(stdout)) == 0 {
		return
	}
	sc := bufio.NewScanner(bytes.NewReader(stdout))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		if !strings.Contains(lower, "login successful") &&
			!strings.Contains(lower, "success") &&
			!strings.HasPrefix(line, "[+]") {
			continue
		}
		// brutespray hit format: "... - <host:port> - <user>:<pass>". The final
		// " - " section is the credential; register the whole token plus the
		// post-colon secret so either form is scrubbed from logs.
		sections := strings.Split(line, " - ")
		cred := strings.TrimSpace(sections[len(sections)-1])
		if !strings.Contains(cred, ":") {
			continue
		}
		log.RegisterHandlerSecret(logger, cred)
		if idx := strings.LastIndexByte(cred, ':'); idx >= 0 && idx < len(cred)-1 {
			log.RegisterHandlerSecret(logger, cred[idx+1:])
		}
	}
}

// parseBrutesprayHits parses brutespray stdout for successful-login lines and
// returns REDACTED credential findings. brutespray prints hits like:
//
//	[+] ssh - Login Successful - 1.2.3.4:22 - admin:hunter2
//
// XCUT-07: the user:password suffix is NEVER copied into the record — only the
// host:port (and service, when present) is retained; PayloadRedacted="***".
func parseBrutesprayHits(stdout []byte) []VulnFindingRecord {
	if len(bytes.TrimSpace(stdout)) == 0 {
		return nil
	}
	var findings []VulnFindingRecord
	sc := bufio.NewScanner(bytes.NewReader(stdout))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		// brutespray success indicators.
		if !strings.Contains(lower, "login successful") &&
			!strings.Contains(lower, "success") &&
			!strings.HasPrefix(line, "[+]") {
			continue
		}
		// Extract a host:port target token — everything after it (the credential)
		// is discarded. Split on " - " sections (brutespray hit format).
		hostPort, service := sprayExtractTarget(line)
		matched := hostPort
		if service != "" {
			matched = service + " " + hostPort
		}
		findings = append(findings, VulnFindingRecord{
			Host:            findingHost(hostPort), // scope-gate locator, port stripped
			Severity:        "high",
			Confidence:      "high",
			VulnClass:       "credential-spray",
			MatchedParam:    strings.TrimSpace(matched), // host/service/port only — no credential (XCUT-07)
			PayloadRedacted: "***",                      // discovered credential never written
			PoCRedacted:     "***",
			Engine:          "brutespray",
		})
	}
	return findings
}

// sprayExtractTarget pulls the host:port and (best-effort) service name from a
// brutespray hit line, discarding any credential material. Returns
// ("host:port", "service") — either may be "" if not found.
// sprayResolveScopeHosts rewrites IP-literal locators back to the in-scope
// hostname that resolved to them.
//
// brutespray and brutus both take their targets from the nmap .gnmap, so their
// hits identify services by IP. Under a domain scope (*.example.com) an IP
// literal is out of scope, so the findings merge dropped every credential-spray
// result — the highest-severity findings the pipeline can produce, discarded
// silently. The scan already knows the mapping: artefacts/hosts.jsonl pairs
// host and ip (written by web.httpx and the subdomains geo enrichment).
//
// A finding whose IP is not in that index keeps the IP as its locator. That is
// correct, not a fallback: under an IP or CIDR target scope the IP is exactly
// the right locator, and under a domain scope an unmappable IP genuinely has no
// in-scope identity.
func sprayResolveScopeHosts(app *appctx.AppContext, findings []VulnFindingRecord) []VulnFindingRecord {
	if len(findings) == 0 || app == nil || app.Target == nil {
		return findings
	}
	// Only pay for the index if at least one locator is an IP literal.
	needed := false
	for _, f := range findings {
		if net.ParseIP(f.Host) != nil {
			needed = true
			break
		}
	}
	if !needed {
		return findings
	}

	index := sprayHostsByIP(app)
	if len(index) == 0 {
		return findings
	}
	for i := range findings {
		if net.ParseIP(findings[i].Host) == nil {
			continue
		}
		if host, ok := index[findings[i].Host]; ok && host != "" {
			if app.Log != nil {
				app.Log.Debug("vulns.spray: mapped service IP back to its in-scope host",
					"ip", findings[i].Host, "host", host)
			}
			findings[i].Host = host
		}
	}
	return findings
}

// sprayHostsByIP builds an ip → hostname index from artefacts/hosts.jsonl.
// Both writers of that artefact (web.httpx HostRecord and the subdomains geo
// HostRecord) carry "host" and "ip", so one decode shape covers both. The first
// host seen for an IP wins, keeping the result deterministic for shared IPs.
func sprayHostsByIP(app *appctx.AppContext) map[string]string {
	path := filepath.Join(app.Target.WorkDir, "artefacts", "hosts.jsonl")
	f, err := os.Open(path) //nolint:gosec // path is workspace-internal
	if err != nil {
		return nil
	}
	defer f.Close() //nolint:errcheck

	index := make(map[string]string)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		var rec struct {
			Host string `json:"host"`
			IP   string `json:"ip"`
		}
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			continue
		}
		if rec.IP == "" || rec.Host == "" {
			continue
		}
		if _, seen := index[rec.IP]; !seen {
			index[rec.IP] = rec.Host
		}
	}
	return index
}

func sprayExtractTarget(line string) (hostPort, service string) {
	// service: first " - "-delimited token after a leading "[+]" marker.
	trimmed := strings.TrimPrefix(line, "[+]")
	sections := strings.Split(trimmed, " - ")
	if len(sections) > 0 {
		cand := strings.TrimSpace(sections[0])
		// A short single-word token before "Login Successful" is the service name.
		if cand != "" && !strings.Contains(cand, ":") && len(strings.Fields(cand)) == 1 {
			service = cand
		}
	}
	// host:port: the first token matching <host>:<numeric-port>.
	for _, tok := range strings.FieldsFunc(line, func(r rune) bool {
		return r == ' ' || r == '\t'
	}) {
		tok = strings.TrimRight(tok, ".,;")
		if h, p, ok := spraySplitHostPort(tok); ok {
			hostPort = h + ":" + p
			break
		}
	}
	return hostPort, service
}

// spraySplitHostPort returns (host, port, true) when tok is "<host>:<digits>"
// with a plausible numeric port, else ("","",false).
func spraySplitHostPort(tok string) (host, port string, ok bool) {
	idx := strings.LastIndexByte(tok, ':')
	if idx <= 0 || idx == len(tok)-1 {
		return "", "", false
	}
	host = tok[:idx]
	port = tok[idx+1:]
	if host == "" || strings.Contains(host, "/") {
		return "", "", false
	}
	if n, err := strconv.Atoi(port); err != nil || n <= 0 || n > 65535 {
		return "", "", false
	}
	return host, port, true
}

// brutusHit is the subset of a brutus --json result line we consume. Credential
// fields (username/password/key) are intentionally NOT decoded — even if present
// they are never read into a finding (XCUT-07 defense in depth).
type brutusHit struct {
	Host    string `json:"host"`
	IP      string `json:"ip"`
	Port    int    `json:"port"`
	Service string `json:"service"`
	Success *bool  `json:"success"`
}

// parseBrutusHits reads the brutus --json output file and returns REDACTED
// credential findings. Only host/service/port is retained; any username/password/
// key present in the JSON is discarded (XCUT-07).
func parseBrutusHits(outPath string) []VulnFindingRecord {
	data, err := os.ReadFile(outPath) //nolint:gosec // path within WorkDir
	if err != nil || len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	var findings []VulnFindingRecord
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var hit brutusHit
		if uErr := json.Unmarshal(line, &hit); uErr != nil {
			continue
		}
		// A record with an explicit success:false is not a finding.
		if hit.Success != nil && !*hit.Success {
			continue
		}
		host := hit.Host
		if host == "" {
			host = hit.IP
		}
		if host == "" && hit.Service == "" && hit.Port == 0 {
			// Not a recognizable brutus hit record — skip.
			continue
		}
		matched := host
		if hit.Port > 0 {
			matched = strings.TrimSpace(host + ":" + strconv.Itoa(hit.Port))
		}
		if hit.Service != "" {
			matched = strings.TrimSpace(hit.Service + " " + matched)
		}
		findings = append(findings, VulnFindingRecord{
			Host:            findingHost(host), // scope-gate locator, port stripped
			Severity:        "high",
			Confidence:      "high",
			VulnClass:       "credential-spray",
			MatchedParam:    strings.TrimSpace(matched), // host/service/port only (XCUT-07)
			PayloadRedacted: "***",                      // discovered credential never written
			PoCRedacted:     "***",
			Engine:          "brutus",
		})
	}
	return findings
}

// sprayFileNonEmpty reports whether path exists, is a regular file, and has
// non-zero size.
func sprayFileNonEmpty(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular() && info.Size() > 0
}

// init self-registers SprayTask with the Default task registry.
// cmd/reconftw/modules.go blank-imports this package to trigger registration.
func init() { task.Register(&SprayTask{}) }

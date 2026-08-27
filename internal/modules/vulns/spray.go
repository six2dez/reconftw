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
// BRUTUS STDIN SEAM — 18-04: NO LONGER A BYPASS.
// brutus reads the service-fingerprint JSON on STDIN (bash: `brutus ... <input`).
// The name-keyed Runner had no stdin channel when this landed, so brutus was
// invoked through the brutusRunner package var with a direct exec.CommandContext.
// 18-01 shipped ExecOptions.StdinPath — a PATH the backend opens, which is
// exactly this call's shape (it already opened a file) and the only site in
// phase 18 that uses it rather than a byte slice. The package var survives as a
// TEST SEAM only; the dispatch inside it now goes through app.Tools.RunOpts.
// brutespray takes a `-f <file>` argument and always routed through
// app.Tools.Run.
//
// THE DEADLINE, RECONCILED RATHER THAN INHERITED. This file applied
// brutusTimeout = 30 minutes while the brutus row in tools.lock declared
// timeout_seconds = 0, which means NO BOUND. Moving the dispatch onto the Runner
// makes tools.lock the sole owner of the deadline, so leaving the manifest at 0
// would have SILENTLY converted a bounded credential-spraying run into an
// unbounded one against a third party (T-18-04-01). The manifest now carries
// 1800 with its derivation, and TestBrutusDeadlineMatchesItsFormerBound pins the
// two together so they cannot drift apart again.
//
// DEFAULT ARGS: the brutus row carries default_args = [], so the argv is
// byte-for-byte the pre-move `--json -o <path> [-u][-p][-k]`.
//
// XCUT-07 (T-13-07-03) — SPRAYED CREDENTIALS ARE NEVER PERSISTED:
// Discovered credentials MUST NOT be written to the JSONL findings. Only the
// host / service / port that accepted a weak credential is recorded; the
// user:password (or key) is redacted to "***" (PayloadRedacted/PoCRedacted).
// brutus -u/-p carry live comma-separated values and are registered with the
// recorder's redactor before dispatch; -k alone carries a file path.
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
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
	"github.com/six2dez/reconftw/internal/core/log"
	"github.com/six2dez/reconftw/internal/core/task"
)

// brutusToolName is the tools.lock registry key.
const brutusToolName = "brutus"

// brutusFormerTimeout is the bound THIS FILE used to apply with its own
// context.WithTimeout, kept as the written derivation for the tools.lock
// timeout_seconds = 1800 that replaced it.
//
// It is not dead: TestBrutusDeadlineMatchesItsFormerBound (in
// internal/core/backend) asserts the manifest value equals 30 minutes, so
// silently setting the manifest back to 0 — which would make a credential
// spraying run unbounded — is a failing diff rather than an invisible one.
const brutusFormerTimeout = 30 * time.Minute //nolint:unused // retained derivation; see the comment above — the pin test duplicates the literal on purpose

// errBrutusNotInstalled is the sentinel returned by brutusRunner when brutus
// could not be dispatched at all (D-V7 graceful skip). It is now derived from
// the Runner's typed dispatch-failure label rather than from exec.LookPath, so
// it additionally covers a tool that is registered but has no resolved path.
var errBrutusNotInstalled = errors.New("brutus not installed")

// brutusRunner runs brutus with the service-fingerprint JSON at serviceFPPath
// piped on STDIN (bash: `brutus ... <input`) and the given argv. Overridable in
// tests. Returns errBrutusNotInstalled when brutus could not be dispatched so a
// missing optional tool degrades to StatusSkipped instead of failing the
// pipeline.
//
// XCUT-07: the service fingerprints cross on STANDARD INPUT and StdinPath never
// reaches the recorder. Configured -u/-p values do reach argv, so runBrutus must
// register them with app.Secrets before this call. Both halves are asserted by
// the spray seam tests rather than assumed to have survived the move.
var brutusRunner = func(ctx context.Context, app *appctx.AppContext, serviceFPPath string, args []string) error {
	if app == nil || app.Tools == nil {
		return errBrutusNotInstalled
	}
	// StdinPath, not Stdin: the backend opens and closes the file itself, so the
	// service-fingerprint payload is never held in this process's memory and
	// never crosses the recorder seam.
	_, err := app.Tools.RunOpts(ctx, brutusToolName, args,
		backend.ExecOptions{StdinPath: serviceFPPath})
	if err != nil {
		if coreerrors.IsDispatchFailure(err) {
			return errBrutusNotInstalled // never started — graceful skip
		}
		return err
	}
	return nil
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
	sprayRegisterBrutesprayCreds(app, stdout)

	findings := sprayResolveScopeHosts(app, parseBrutesprayHits(stdout))

	// brutespray RAN: an absent or failing binary returned StatusSkipped above,
	// so reaching here means zero findings is a real observation (F3).
	sprayWriteFindings(app, true, findings)

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

	// XCUT-07, CORRECTED IN 18-04. The comment that stood here claimed
	// "credential wordlists cross as FILE PATHS only (never raw values)". That is
	// TRUE of -k and FALSE of -u and -p: `brutus --help` on the installed build
	// documents them as
	//
	//	-u <usernames>   Comma-separated usernames (default: "root,admin")
	//	-p <passwords>   Comma-separated passwords
	//	-k <keyfile>     SSH private key file
	//
	// so a configured advanced.tools.brutus.passwords is a LIST OF LIVE
	// PASSWORDS placed on argv. That was survivable only while this file
	// dispatched brutus itself: 18-04 routes it through backend.Runner, whose
	// recorder writes argv into logs/tools.jsonl — a file operators paste into
	// issue reports (T-18-04-03).
	//
	// So register each configured value BEFORE the dispatch, through app.Secrets —
	// the SecretRegistrar seam appctx.Boot points at the ToolRecorder's OWN
	// redactor. The earlier version of this comment claimed the recorder "holds the
	// SAME redactor instance the logger does"; it does not, and registering only
	// with app.Log left the credentials in clear text on every non-TTY run (CR-01).
	// Pinned by TestSprayConfiguredCredentialsAreNotRecorded, which now builds two
	// distinct redactors so it models production and can fail.
	//
	// WR-09: the flag is appended ONLY if registration actually reached the
	// recorder's redactor. It used to be appended unconditionally, so a run with no
	// registrar — every MCP-driven scan before V-01 — dispatched live credentials
	// into logs/tools.jsonl with nothing to scrub them and nothing said about it.
	// Omitting the flag degrades the scan (brutus falls back to its own defaults);
	// writing the password to a file operators paste into issue reports does not
	// degrade anything, it just loses the credential. The loud, lesser harm wins.
	if u := strings.TrimSpace(app.Cfg.Advanced.Tools.Brutus.Usernames); u != "" {
		if sprayRegisterConfiguredCreds(app, u) {
			args = append(args, "-u", u)
		} else if app.Log != nil {
			app.Log.Warn("vulns.spray: configured brutus usernames could NOT be registered " +
				"with the run redactor — omitting -u rather than writing live credentials " +
				"to logs/tools.jsonl (WR-09)")
		}
	}
	if p := strings.TrimSpace(app.Cfg.Advanced.Tools.Brutus.Passwords); p != "" {
		if sprayRegisterConfiguredCreds(app, p) {
			args = append(args, "-p", p)
		} else if app.Log != nil {
			app.Log.Warn("vulns.spray: configured brutus passwords could NOT be registered " +
				"with the run redactor — omitting -p rather than writing live credentials " +
				"to logs/tools.jsonl (WR-09)")
		}
	}
	// -k is a PATH, not a value: it is left unregistered on purpose, because
	// redacting a filesystem path would only make the record harder to read
	// without protecting anything the record did not already lack.
	if k := strings.TrimSpace(app.Cfg.Advanced.Tools.Brutus.KeyFile); k != "" {
		args = append(args, "-k", k)
	}

	err := brutusRunner(ctx, app, serviceFP, args)
	// brutusRan is false only when the binary is absent: brutus never observed
	// the service list, so it must not clear a previous run's staging (F3
	// did-not-run — staging.go). Any OTHER error still means brutus ran and may
	// have produced partial output, which is parsed below.
	brutusRan := !errors.Is(err, errBrutusNotInstalled)
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
	sprayRegisterBrutusCreds(app, outPath)

	// Parse brutus JSONL output; XCUT-07: only host/service/port recorded, creds redacted.
	findings := sprayResolveScopeHosts(app, parseBrutusHits(outPath))
	sprayWriteFindings(app, brutusRan, findings)

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
// file inputs/findings.spray.jsonl (consumed by MergeAllVulnsArtefacts).
//
// F3 (phase 15): the write is UNCONDITIONAL. `ran` says whether the spray engine
// was actually dispatched; when it was and no credential was accepted, the
// staging file is REMOVED, so a password that has since been rotated stops being
// reported as still weak by every later run. XCUT-07 is unaffected: the records
// handed here already carry "***" in PayloadRedacted/PoCRedacted and no
// credential value ever reaches this function.
func sprayWriteFindings(app *appctx.AppContext, ran bool, findings []VulnFindingRecord) {
	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if len(findings) > 0 {
		if err := os.MkdirAll(inputsDir, 0o755); err != nil {
			if app.Log != nil {
				app.Log.Debug("vulns.spray: mkdir inputs/ failed (best_effort)", "error", err.Error())
			}
			return
		}
	}
	stagingPath := filepath.Join(inputsDir, "findings.spray.jsonl")
	stageVulnFindings(app, "vulns.spray", stagingPath, ran, findings)
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

// sprayRegisterSecret registers one credential value with BOTH redaction sinks.
//
// WHY BOTH, and why app.Secrets is the load-bearing one (18-06 code review, CR-01
// + phase verification Gap 1). 18-04 registered configured brutus credentials with
// log.RegisterHandlerSecret(app.Log, ...) alone, under a comment asserting "the
// ToolRecorder holds the SAME redactor instance the logger does". appctx.Boot does
// not wire them that way:
//
//   - the ToolRecorder is built with BootOptions.Redactor (boot.go), which is the
//     per-run redactor a subcommand creates via newRunRedactor();
//   - app.Log at Boot time is the CLI logger, backed by a DIFFERENT redactor
//     instance — loglevel.go documents its own as one that does NOT learn
//     runtime-registered secrets;
//   - the two only converge inside `if liveUI {`, i.e. an interactive TTY.
//
// So on CI, under nohup, with --quiet, or with stderr redirected — precisely the
// runs whose logs get archived and pasted into issues — the recorder's redactor
// never learned the password and wrote it verbatim into logs/tools.jsonl:
//
//	"argv":[...,"-u","admin","-p","<the operator's real password>"]
//
// app.Secrets is the SecretRegistrar seam Boot points at the SAME redactor the
// recorder holds, which is why subdomains/passive.go already registers through it.
// The log sink is kept as well so a later log line echoing one credential is also
// scrubbed; neither sink subsumes the other.
//
// Redactor.Register skips values of four characters or fewer — the redactor's own
// documented floor, restated here rather than papered over.
// It REPORTS whether the value actually reached the recorder's sink (WR-09).
// A caller that is about to put the value on argv must not proceed on a false:
// registering nowhere and dispatching anyway produces exactly the plaintext record
// this function exists to prevent, with nothing said about it.
//
// Only app.Secrets counts toward the return value. The log sink is registered as
// well, but it does not protect logs/tools.jsonl — under the MCP transport before
// V-01 it was the ONLY sink present, and the record was written in clear text
// regardless. Values of four characters or fewer also return false because the
// production log.Redactor deliberately refuses to register them; an argv caller
// must omit such a value rather than mistake a non-nil registrar for protection.
func sprayRegisterSecret(app *appctx.AppContext, value string) bool {
	v := strings.TrimSpace(value)
	if app == nil || len(v) <= 4 {
		return false
	}
	registered := false
	if app.Secrets != nil {
		app.Secrets.Register(v)
		registered = true
	}
	if app.Log != nil {
		log.RegisterHandlerSecret(app.Log, v)
	}
	return registered
}

// sprayRegisterBrutusCreds reads brutus's raw --json hit file and registers every
// discovered credential (username/password/key) with BOTH redaction sinks via
// sprayRegisterSecret — the recorder's redactor AND the log one (CR-01) — so a
// later log line or recorded argv echoing it is scrubbed (WR-13-03). Values are read transiently
// and NEVER copied into a finding (XCUT-07 — findings carry "***").
func sprayRegisterBrutusCreds(app *appctx.AppContext, outPath string) {
	if app == nil {
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
			sprayRegisterSecret(app, v)
		}
	}
}

// sprayRegisterConfiguredCreds registers a comma-separated brutus credential
// list, and each of its elements, with the run Redactor (Layer 2) so neither the
// whole argument nor any single credential survives into logs/tools.jsonl or any
// later log line.
//
// BOTH forms are registered on purpose: the recorder scrubs each argv ELEMENT,
// which is the joined string, while a log line elsewhere may echo one credential
// on its own. Redactor.Register skips values of four characters or fewer. If
// ANY element is that short, registration therefore fails closed and runBrutus
// omits the whole flag: the child could echo that element alone into the
// recorder's stderr tail even when the joined argv element was scrubbed.
func sprayRegisterConfiguredCreds(app *appctx.AppContext, list string) bool {
	if app == nil || list == "" {
		return false
	}
	parts := strings.Split(list, ",")
	for _, part := range parts {
		if len(strings.TrimSpace(part)) <= 4 {
			return false
		}
	}
	// The WHOLE list is the argv element the recorder scrubs, so its registration
	// is the one that decides. Element registrations are additive protection for a
	// later log line or stderr tail echoing one credential on its own. Every
	// element passed the redactor's length floor above; otherwise the whole flag
	// is omitted even when the joined argv element itself could be scrubbed.
	registered := sprayRegisterSecret(app, list)
	for _, part := range parts {
		sprayRegisterSecret(app, part)
	}
	return registered
}

// sprayRegisterBrutesprayCreds extracts the trailing user:pass from each
// brutespray success line and registers it with BOTH redaction sinks via
// sprayRegisterSecret (CR-01) so a later log line or recorded argv echoing it is
// scrubbed (WR-13-03). The credential is NEVER copied into
// a finding (XCUT-07 — parseBrutesprayHits redacts to "***").
func sprayRegisterBrutesprayCreds(app *appctx.AppContext, stdout []byte) {
	if app == nil || len(bytes.TrimSpace(stdout)) == 0 {
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
		sprayRegisterSecret(app, cred)
		if idx := strings.LastIndexByte(cred, ':'); idx >= 0 && idx < len(cred)-1 {
			sprayRegisterSecret(app, cred[idx+1:])
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
// sprayResolveScopeHosts attaches every hostname known to resolve to a spray
// finding's IP, and records a single unambiguous hostname as the locator.
//
// brutespray and brutus both take their targets from the nmap .gnmap, so their
// hits identify a service by IP ADDRESS. That IP is the only claim the result
// actually supports: a weak credential was accepted at 10.0.0.5:22. It says
// nothing about which of the names pointing at 10.0.0.5 owns that service.
//
// F20 (audit finding, bullet 3). This function used to overwrite Host with
// whichever hostname happened to appear FIRST for that IP in hosts.jsonl,
// justified in a comment as "keeping the result deterministic for shared IPs".
// Determinism is not correctness. On shared hosting or a CDN edge, dozens of
// unrelated names share one address, and filing a SUCCESSFUL CREDENTIAL SPRAY
// against an arbitrary one of them is the highest-consequence attribution error
// this tool can make: the finding names a domain that may have no relationship
// to the service, and a disclosure sent on that basis reports unauthorised
// access against an uninvolved party.
//
// The rule now:
//
//   - EXACTLY ONE hostname for the IP → unambiguous. Host becomes that hostname
//     and Hostnames carries it as its single entry. Nothing is guessed.
//   - MORE THAN ONE → ambiguous. Host stays the IP LITERAL, and Hostnames
//     carries every candidate in first-seen order so a reviewer sees the full
//     relation instead of an invented one.
//   - NOT IN THE INDEX → Host stays the IP literal. That is correct, not a
//     fallback: under an IP or CIDR target scope the IP is exactly the right
//     locator, and under a domain scope an unmappable IP genuinely has no
//     in-scope identity.
//
// An IP-literal Host still passes the findings scope gate whenever the address
// itself is in scope — output.FilterInScope resolves a findings record through
// Tree.InScope, and the IP/CIDR scope support an earlier audit added admits it.
// That matters: dropping these at the scope boundary is the failure mode the
// single-hostname rewrite was originally introduced to avoid, and it must not
// come back while the attribution is being fixed.
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
		ip := findings[i].Host
		if net.ParseIP(ip) == nil {
			continue
		}
		hosts := index[ip]
		if len(hosts) == 0 {
			continue
		}
		// Preserve the relation to EVERY candidate name, always.
		findings[i].Hostnames = append([]string(nil), hosts...)
		if len(hosts) == 1 {
			// Unambiguous: exactly one name resolves here, so naming it is a
			// statement of fact rather than a guess.
			findings[i].Host = hosts[0]
		}
		if app.Log != nil {
			// XCUT-07: the IP and hostnames are non-secret locators; the
			// credential never reaches this function. The previous message said
			// the service IP had been mapped back to ITS in-scope host — the
			// singular possessive was itself the unsupported claim. Log what is
			// actually known: how many names share the address, and whether that
			// makes the attribution ambiguous.
			app.Log.Debug("vulns.spray: service IP associated with known hostnames",
				"ip", ip, "hostnames", len(hosts), "ambiguous", len(hosts) > 1)
		}
	}
	return findings
}

// sprayHostsByIP builds an ip → []hostname index from artefacts/hosts.jsonl,
// in first-seen order and deduplicated.
//
// Both writers of that artefact (web.httpx HostRecord and the subdomains geo
// HostRecord) carry "host" and "ip", so one decode shape covers both.
//
// F20: this returned map[string]string with a first-wins guard. A shared IP
// legitimately has MANY hostnames, and discarding all but one does not make the
// answer right — it makes a wrong answer stable. Every name is kept so the
// caller can tell "one name, therefore certain" from "many names, therefore
// ambiguous"; that distinction is the whole fix.
func sprayHostsByIP(app *appctx.AppContext) map[string][]string {
	path := filepath.Join(app.Target.WorkDir, "artefacts", "hosts.jsonl")
	f, err := os.Open(path) //nolint:gosec // path is workspace-internal
	if err != nil {
		return nil
	}
	defer f.Close() //nolint:errcheck

	index := make(map[string][]string)
	seen := make(map[string]map[string]struct{})
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
		if seen[rec.IP] == nil {
			seen[rec.IP] = make(map[string]struct{})
		}
		if _, dup := seen[rec.IP][rec.Host]; dup {
			continue
		}
		seen[rec.IP][rec.Host] = struct{}{}
		index[rec.IP] = append(index[rec.IP], rec.Host)
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

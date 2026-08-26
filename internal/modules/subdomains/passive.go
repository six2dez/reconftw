// passive.go — 6 passive subdomain Tasks + exported JSONL record types.
//
// STAGING CONTRACT (doc.go): Tasks write raw hostnames to per-source staging
// files at filepath.Join(app.Target.WorkDir, "inputs", "passive."+toolName+".txt").
// Tasks do NOT call app.Tree.Append directly — MergeStage (merge.go) is the
// single app.Tree.Append caller for the passive stage.
//
// JSONL SCHEMAS (downstream contract):
//   - SubdomainRecord: written to artefacts/subdomains.jsonl by MergeStage.
//   - TakeoverRecord:  written to artefacts/findings.jsonl by Phase 4 plan-02.
//   - BucketRecord:    written to artefacts/buckets.jsonl by Phase 4 plan-02.
//   - ASNRecord:       written to artefacts/asns.jsonl by Phase 4 plan-05.
//   - HostRecord:      written to artefacts/hosts.jsonl by Phase 5.
//
// Source: .planning/phases/04-subdomains-e2e-axiom-integration/04-01-PLAN.md
// Task 1 Step B (record schemas) + Task 2 (Task implementations).
package subdomains

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/core/task"
)

// -------------------------------------------------------------------------
// JSONL Record Types (exported — downstream contract for Phase 5 + Phase 10)
// -------------------------------------------------------------------------

// SubdomainRecord is the JSONL schema for artefacts/subdomains.jsonl.
// Written by MergeStage after deduplication of all passive.*.txt staging files.
type SubdomainRecord struct {
	Subdomain string `json:"subdomain"`
	Source    string `json:"source"`
	FirstSeen string `json:"first_seen"`
}

// TakeoverRecord is the JSONL schema for artefacts/findings.jsonl (takeover class).
// Written by TakeoverSubzyTask / TakeoverDNSTakeTask in Phase 4 plan-02.
type TakeoverRecord struct {
	Type       string   `json:"type"`
	Host       string   `json:"host"`
	Service    string   `json:"service"`
	Confidence string   `json:"confidence"`
	Severity   string   `json:"severity"`
	Refs       []string `json:"refs"`
}

// BucketRecord is the JSONL schema for artefacts/buckets.jsonl.
// Written by S3BucketsTask in Phase 4 plan-02.
type BucketRecord struct {
	Provider string `json:"provider"`
	Name     string `json:"name"`
	URL      string `json:"url"`
	Access   string `json:"access"`
}

// ASNRecord is the JSONL schema for artefacts/asns.jsonl.
// Written by ASNTask in Phase 4 plan-05.
type ASNRecord struct {
	ASN   string   `json:"asn"`
	Org   string   `json:"org"`
	CIDRs []string `json:"cidrs"`
}

// HostRecord is the JSONL schema for artefacts/hosts.jsonl.
// Written by the web/hosts pipeline in Phase 5.
type HostRecord struct {
	Host    string `json:"host"`
	IP      string `json:"ip"`
	ASN     string `json:"asn"`
	Country string `json:"country"`
	City    string `json:"city"`
}

// -------------------------------------------------------------------------
// Passive Tasks
// -------------------------------------------------------------------------

// SubfinderTask runs subfinder passive multi-source subdomain discovery.
// Writes staging file: inputs/passive.subfinder.txt
type SubfinderTask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (SubfinderTask) Name() string { return "subdomains.passive.subfinder" }

// Module returns the owning module group.
func (SubfinderTask) Module() string { return "subdomains" }

// Description returns a human-readable one-line description.
func (SubfinderTask) Description() string {
	return "Passive subdomain enumeration via subfinder (multi-source)"
}

// Enabled reports whether this task should run.
func (SubfinderTask) Enabled(cfg *config.Config) bool {
	return cfg.Subdomains.Passive.Enabled
}

// DependsOn returns nil — all passive Tasks run concurrently in the passive RunStage.
func (SubfinderTask) DependsOn() []string { return nil }

// Run executes subfinder and writes raw hostnames to the staging file.
func (SubfinderTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "subfinder"
	args := []string{
		"-all",
		"-d", app.Target.Domain,
		"-max-time", strconv.Itoa(subfinderMaxTimeMinutes(app)),
		"-silent",
	}
	return runPassiveTask(ctx, app, toolName, args)
}

// defaultSubfinderMaxTimeMinutes mirrors reconftw.cfg:384
// (SUBFINDER_ENUM_TIMEOUT=180 # Minutes) and config.Defaults(). It is the
// fallback for a hand-built *config.Config that never went through Defaults().
const defaultSubfinderMaxTimeMinutes = 180

// subfinderMaxTimeMinutes returns the value for subfinder's -max-time flag in
// the unit subfinder documents.
//
// CR-07. `subfinder -h` on v2.14.0:
//
//	-timeout int   seconds to wait before timing out (default 30)
//	-max-time int  minutes to wait for enumeration results (default 10)
//
// Two time flags with different units, and v2 passed MINUTES x 60 into the one
// that takes minutes. subfinder accepts the number without complaint — it is a
// legal value — so the only visible effect was that subfinder's own budget
// stopped bounding anything, leaving the tools.lock process deadline as the
// sole bound. v1 passes the configured value straight through
// (modules/subdomains.sh:515), with no wrapper and no multiplication.
//
// The WARN below exists because the same inversion can return through config:
// the process deadline in tools.lock silently wins over any -max-time larger
// than itself, and a budget that is silently overruled is exactly the shape
// this phase is removing. Nothing is clamped — the operator's configured value
// is still what subfinder is asked for — but the run says so.
func subfinderMaxTimeMinutes(app *appctx.AppContext) int {
	minutes := defaultSubfinderMaxTimeMinutes
	if app.Cfg != nil && app.Cfg.Advanced.Tools.Subfinder.TimeoutMinutes > 0 {
		minutes = app.Cfg.Advanced.Tools.Subfinder.TimeoutMinutes
	}
	if app.Log == nil || app.Tools == nil || app.Tools.Registry == nil {
		return minutes
	}
	tool, ok := app.Tools.Registry.Lookup("subfinder")
	if !ok || tool.Timeout <= 0 {
		return minutes
	}
	if requested := time.Duration(minutes) * time.Minute; tool.Timeout < requested {
		app.Log.Warn("subfinder_budget_exceeds_process_deadline",
			"requested_minutes", minutes,
			"process_deadline_seconds", int(tool.Timeout.Seconds()),
			"effect", "subfinder will be killed at the process deadline; the configured budget is not what it gets",
			"fix", "raise timeout_seconds for subfinder in tools.lock, or lower advanced.tools.subfinder.timeout_minutes")
	}
	return minutes
}

// CrtTask queries crt.sh for subdomain records.
// Writes staging file: inputs/passive.crt.txt
type CrtTask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (CrtTask) Name() string { return "subdomains.passive.crt" }

// Module returns the owning module group.
func (CrtTask) Module() string { return "subdomains" }

// Description returns a human-readable one-line description.
func (CrtTask) Description() string {
	return "Passive subdomain enumeration via crt.sh certificate transparency logs"
}

// Enabled reports whether this task should run.
func (CrtTask) Enabled(cfg *config.Config) bool {
	return cfg.Subdomains.Passive.Enabled
}

// DependsOn returns nil.
func (CrtTask) DependsOn() []string { return nil }

// Run executes the crt tool and writes parsed hostnames to the staging file.
//
// cemulus/crt CLI quirks (verified against crt v0.1.0 --help and live runs):
//   - The domain is a POSITIONAL argument (no -d flag).
//   - DEFAULT output is a decorated ANSI box-table and can PANIC
//     (index out of range in CertResult.Table) on some inputs.
//   - Even `-s` (enumerate subdomains) prints a colored box-table whose
//     border lines (`+———+`) are NOT hostnames — feeding them through the
//     line scanner pollutes the staging set and trips the scope filter.
//   - Only `-s -json` yields machine-parseable output:
//     `[{"subdomain": "<value>"}, ...]`. Values can include certificate-CN
//     noise (e.g. "AS207960 Test Intermediate - example.com"); we keep only
//     values shaped like real hostnames (no whitespace, contains a dot) and
//     strip any leading "*." wildcard label. The scope filter (merge.go) is
//     the final authority on in-scope membership.
func (CrtTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "crt"
	args := []string{"-s", "-json", app.Target.Domain}

	res, err := app.Tools.Run(ctx, toolName, args)
	if err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("%s: tool execution failed: %w", toolName, err)
	}

	hostnames := parseCrtJSON(res.Stdout)

	stagingPath, writeErr := writeStagingFile(app, toolName, hostnames)
	if writeErr != nil {
		return task.Result{Status: task.StatusErrored}, writeErr
	}

	return task.Result{
		Status:  task.StatusDone,
		Outputs: []string{stagingPath},
		Stats:   map[string]int{"subdomains_found": len(hostnames)},
	}, nil
}

// parseCrtJSON parses `crt -s -json` output (a JSON array of {"subdomain": ...})
// into a deduplicated list of hostname-shaped values. Non-hostname values
// (certificate CNs with spaces, blanks) are dropped; leading "*." wildcard
// labels are stripped. Falls back to empty on malformed JSON rather than
// erroring — a passive source producing garbage must not abort the stage.
func parseCrtJSON(stdout []byte) []string {
	var records []struct {
		Subdomain string `json:"subdomain"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(stdout), &records); err != nil {
		return nil
	}
	seen := make(map[string]bool, len(records))
	var hostnames []string
	for _, rec := range records {
		h := strings.ToLower(strings.TrimSpace(rec.Subdomain))
		h = strings.TrimPrefix(h, "*.")
		// Reject cert-CN noise: a hostname has no whitespace and at least one dot.
		if h == "" || strings.ContainsAny(h, " \t") || !strings.Contains(h, ".") {
			continue
		}
		if seen[h] {
			continue
		}
		seen[h] = true
		hostnames = append(hostnames, h)
	}
	return hostnames
}

// GithubSubdomainsTask discovers subdomains via GitHub search using a token file.
// Writes staging file: inputs/passive.github-subdomains.txt
// Enabled only when cfg.Paths.GitHubTokens is non-empty.
type GithubSubdomainsTask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (GithubSubdomainsTask) Name() string { return "subdomains.passive.github" }

// Module returns the owning module group.
func (GithubSubdomainsTask) Module() string { return "subdomains" }

// Description returns a human-readable one-line description.
func (GithubSubdomainsTask) Description() string {
	return "Passive subdomain enumeration via GitHub search (requires tokens file)"
}

// Enabled reports whether this task should run.
// Requires both cfg.Subdomains.Passive.Enabled AND a non-empty token file path.
func (GithubSubdomainsTask) Enabled(cfg *config.Config) bool {
	return cfg.Subdomains.Passive.Enabled && cfg.Paths.GitHubTokens != ""
}

// DependsOn returns nil.
func (GithubSubdomainsTask) DependsOn() []string { return nil }

// Run executes github-subdomains and writes raw hostnames to the staging file.
// XCUT-07: token file contents are registered as secrets before any logging.
func (GithubSubdomainsTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "github-subdomains"
	tokenFile := app.Cfg.Paths.GitHubTokens

	// Read token content so we can register it as a secret (XCUT-07 T-04-01-02).
	tokenBytes, err := os.ReadFile(tokenFile) //nolint:gosec // path validated at Target creation
	if err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("github-subdomains: read token file %q: %w", tokenFile, err)
	}
	tokenStr := strings.TrimSpace(string(tokenBytes))

	// Register the token the moment it exists in memory and BEFORE dispatch.
	//
	// This was promised and not done: the code only logged the token's LENGTH.
	// Survivable while argv stayed in memory; not survivable once
	// logs/tools.jsonl began writing argv to disk, because this task puts the
	// token's CONTENT on the command line (`-t <token>`, below).
	//
	// ARCH-02 says v2 never passes a secret as a CLI arg. This site VIOLATES that,
	// and registering the token does NOT fix the violation — moving to RunEnv
	// would change the tool's own contract. What this guarantees is that the
	// violation does not become a plaintext token in a file.
	if tokenStr != "" && app.Secrets != nil {
		app.Secrets.Register(tokenStr)
	}
	if tokenStr != "" && app.Log != nil {
		app.Log.Debug("github-subdomains: token file loaded",
			"file", tokenFile,
			"len", len(tokenStr),
		)
	}

	args := []string{"-d", app.Target.Domain, "-t", tokenStr}
	return runPassiveTask(ctx, app, toolName, args)
}

// GitlabSubdomainsTask discovers subdomains via GitLab search using a token file.
// Writes staging file: inputs/passive.gitlab-subdomains.txt
// Enabled only when cfg.Paths.GitLabTokens is non-empty.
type GitlabSubdomainsTask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (GitlabSubdomainsTask) Name() string { return "subdomains.passive.gitlab" }

// Module returns the owning module group.
func (GitlabSubdomainsTask) Module() string { return "subdomains" }

// Description returns a human-readable one-line description.
func (GitlabSubdomainsTask) Description() string {
	return "Passive subdomain enumeration via GitLab search (requires tokens file)"
}

// Enabled reports whether this task should run.
// Requires both cfg.Subdomains.Passive.Enabled AND a non-empty token file path.
func (GitlabSubdomainsTask) Enabled(cfg *config.Config) bool {
	return cfg.Subdomains.Passive.Enabled && cfg.Paths.GitLabTokens != ""
}

// DependsOn returns nil.
func (GitlabSubdomainsTask) DependsOn() []string { return nil }

// Run executes gitlab-subdomains and writes raw hostnames to the staging file.
// XCUT-07: token file contents are registered as secrets before any logging.
func (GitlabSubdomainsTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "gitlab-subdomains"
	tokenFile := app.Cfg.Paths.GitLabTokens

	// Read token content so we can register it as a secret (XCUT-07 T-04-01-02).
	tokenBytes, err := os.ReadFile(tokenFile) //nolint:gosec // path validated at Target creation
	if err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("gitlab-subdomains: read token file %q: %w", tokenFile, err)
	}
	tokenStr := strings.TrimSpace(string(tokenBytes))

	// Register the token the moment it exists in memory and BEFORE dispatch.
	//
	// This was promised and not done: the code only logged the token's LENGTH.
	// Survivable while argv stayed in memory; not survivable once
	// logs/tools.jsonl began writing argv to disk, because this task puts the
	// token's CONTENT on the command line (`-t <token>`, below).
	//
	// ARCH-02 says v2 never passes a secret as a CLI arg. This site VIOLATES that,
	// and registering the token does NOT fix the violation — moving to RunEnv
	// would change the tool's own contract. What this guarantees is that the
	// violation does not become a plaintext token in a file.
	if tokenStr != "" && app.Secrets != nil {
		app.Secrets.Register(tokenStr)
	}
	if tokenStr != "" && app.Log != nil {
		app.Log.Debug("gitlab-subdomains: token file loaded",
			"file", tokenFile,
			"len", len(tokenStr),
		)
	}

	args := []string{"-d", app.Target.Domain, "-t", tokenStr}
	return runPassiveTask(ctx, app, toolName, args)
}

// UrlfinderTask discovers subdomains via urlfinder passive URL collection.
// Writes staging file: inputs/passive.urlfinder.txt
type UrlfinderTask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (UrlfinderTask) Name() string { return "subdomains.passive.urlfinder" }

// Module returns the owning module group.
func (UrlfinderTask) Module() string { return "subdomains" }

// Description returns a human-readable one-line description.
func (UrlfinderTask) Description() string {
	return "Passive subdomain enumeration via urlfinder URL collection"
}

// Enabled reports whether this task should run.
func (UrlfinderTask) Enabled(cfg *config.Config) bool {
	return cfg.Subdomains.Passive.Enabled
}

// DependsOn returns nil.
func (UrlfinderTask) DependsOn() []string { return nil }

// Run executes urlfinder and writes raw hostnames to the staging file.
func (UrlfinderTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "urlfinder"
	args := []string{"-d", app.Target.Domain, "-silent"}
	return runPassiveTask(ctx, app, toolName, args)
}

// -------------------------------------------------------------------------
// Shared helpers
// -------------------------------------------------------------------------

// runPassiveTask is the common implementation shared by EVERY passive Task:
// run tool, collect stdout lines as hostnames, write staging file.
//
// It used to say "Tasks with special dispatch (HackertargetTask) call
// writeStagingFile directly instead". That task was the only exception and it
// was deleted in 17-07 (CR-05): it ran `httpx -silent -u <api url>` and parsed
// the result as the API response body, but httpx prints the PROBED URL, so the
// URL itself was staged as a hostname and the task reported one subdomain found
// on every run. There is no longer a special-dispatch passive Task; a future one
// would need its own note here.
func runPassiveTask(ctx context.Context, app *appctx.AppContext, toolName string, args []string) (task.Result, error) {
	res, err := app.Tools.Run(ctx, toolName, args)
	if err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("%s: tool execution failed: %w", toolName, err)
	}

	var hostnames []string
	scanner := bufio.NewScanner(bytes.NewReader(res.Stdout))
	for scanner.Scan() {
		line := strings.ToLower(strings.TrimSpace(scanner.Text()))
		if line != "" {
			hostnames = append(hostnames, line)
		}
	}

	stagingPath, writeErr := writeStagingFile(app, toolName, hostnames)
	if writeErr != nil {
		return task.Result{Status: task.StatusErrored}, writeErr
	}

	return task.Result{
		Status:  task.StatusDone,
		Outputs: []string{stagingPath},
		Stats:   map[string]int{"subdomains_found": len(hostnames)},
	}, nil
}

// writeStagingFile writes hostnames (one per line) to the per-source staging
// file at filepath.Join(app.Target.WorkDir, "inputs", "passive."+toolName+".txt"),
// or REMOVES that file when hostnames is empty. Returns the staging path in
// both cases (the caller records it in task.Result.Outputs, which is stored as
// a string and never stat-ed).
//
// F3 (phase 15): this is write-or-REMOVE via output.StageLines. Calling it is
// the statement "this passive source RAN and these are ALL the hostnames it saw
// this invocation", so a zero-result run clears the file instead of leaving the
// previous run's hostnames for MergeAllSubdomains to republish. A task skipped
// by the checkpoint never gets here, so resume still merges its data.
//
// The staging NAME is frozen: MergeAllSubdomains globs inputs/passive.*.txt
// (see doc.go's STAGING CONTRACT), so renaming this file silently drops the
// source from the merge.
func writeStagingFile(app *appctx.AppContext, toolName string, hostnames []string) (string, error) {
	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return "", fmt.Errorf("passive %s: mkdir inputs/: %w", toolName, err)
	}

	stagingPath := filepath.Join(inputsDir, "passive."+toolName+".txt")
	if err := output.StageLines(stagingPath, hostnames); err != nil {
		return "", fmt.Errorf("passive %s: write staging file: %w", toolName, err)
	}
	return stagingPath, nil
}

// stagingTimestamp returns the current UTC time in RFC3339 format for use
// as the first_seen field in SubdomainRecord.
func stagingTimestamp() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// -------------------------------------------------------------------------
// init() — self-registration via the task registry (staging contract doc.go).
// Blank-import this package in cmd/reconftw/modules.go to trigger these.
// -------------------------------------------------------------------------

func init() { task.Register(SubfinderTask{}) }
func init() { task.Register(CrtTask{}) }
func init() { task.Register(GithubSubdomainsTask{}) }
func init() { task.Register(GitlabSubdomainsTask{}) }
func init() { task.Register(UrlfinderTask{}) }

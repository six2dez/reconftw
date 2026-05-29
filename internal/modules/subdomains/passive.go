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
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
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
	cfg := app.Cfg
	timeoutSecs := cfg.Advanced.Tools.Subfinder.TimeoutMinutes * 60
	args := []string{
		"-all",
		"-d", app.Target.Domain,
		"-max-time", strconv.Itoa(timeoutSecs),
		"-silent",
	}
	return runPassiveTask(ctx, app, toolName, args)
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

// Run executes the crt tool and writes raw hostnames to the staging file.
func (CrtTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "crt"
	args := []string{"-d", app.Target.Domain}
	return runPassiveTask(ctx, app, toolName, args)
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
	// Register token as secret before any logging that may include tool stderr.
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

// HackertargetTask queries the HackerTarget API for reverse IP/subdomain data.
// Uses httpx to fetch https://api.hackertarget.com/hostsearch/?q=<domain>.
// Writes staging file: inputs/passive.hackertarget.txt
type HackertargetTask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (HackertargetTask) Name() string { return "subdomains.passive.hackertarget" }

// Module returns the owning module group.
func (HackertargetTask) Module() string { return "subdomains" }

// Description returns a human-readable one-line description.
func (HackertargetTask) Description() string {
	return "Passive subdomain enumeration via HackerTarget API (hostsearch)"
}

// Enabled reports whether this task should run.
func (HackertargetTask) Enabled(cfg *config.Config) bool {
	return cfg.Subdomains.Passive.Enabled
}

// DependsOn returns nil.
func (HackertargetTask) DependsOn() []string { return nil }

// Run uses httpx to fetch the HackerTarget hostsearch API and parses the
// comma-separated response (subdomain,ip per line). Extracts subdomain column
// only and writes to the staging file.
func (HackertargetTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "hackertarget"
	apiURL := "https://api.hackertarget.com/hostsearch/?q=" + app.Target.Domain
	args := []string{"-silent", "-u", apiURL}

	res, err := app.Tools.Run(ctx, "httpx", args)
	if err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("%s: httpx call failed: %w", toolName, err)
	}

	// HackerTarget returns lines in the form "subdomain.example.com,1.2.3.4"
	// Extract only the subdomain (first field).
	var hostnames []string
	scanner := bufio.NewScanner(bytes.NewReader(res.Stdout))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// Take first CSV field (subdomain), ignore IP column.
		if idx := strings.IndexByte(line, ','); idx > 0 {
			line = line[:idx]
		}
		line = strings.ToLower(strings.TrimSpace(line))
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

// -------------------------------------------------------------------------
// Shared helpers
// -------------------------------------------------------------------------

// runPassiveTask is the common implementation shared by all passive Tasks that
// follow the simple pattern: run tool, collect stdout lines as hostnames,
// write staging file. Tasks with special dispatch (HackertargetTask) call
// writeStagingFile directly instead.
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
// file at filepath.Join(app.Target.WorkDir, "inputs", "passive."+toolName+".txt").
// Creates the inputs/ directory if it does not exist. Returns the absolute
// path written.
func writeStagingFile(app *appctx.AppContext, toolName string, hostnames []string) (string, error) {
	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return "", fmt.Errorf("passive %s: mkdir inputs/: %w", toolName, err)
	}

	stagingPath := filepath.Join(inputsDir, "passive."+toolName+".txt")
	content := strings.Join(hostnames, "\n")
	if len(hostnames) > 0 {
		content += "\n"
	}

	if err := os.WriteFile(stagingPath, []byte(content), 0o644); err != nil { //nolint:gosec
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
func init() { task.Register(HackertargetTask{}) }

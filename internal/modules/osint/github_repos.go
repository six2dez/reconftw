// github_repos.go — GitHubReposTask: org repo enumeration (enumerepo) + full
// company-repo secret scan (titus + trufflehog) (OSINT-05 / PAR-03).
//
// GitHubReposTask runs enumerepo over the company org (v1 osint.sh:68
// github_repos), producing the repository list that feeds the leak scan
// (GitHubLeaksTask, D-O10 fold: github_repos + github_leaks → OSINT-05).
//
// It then performs the heavy bash github_repos secret pipeline (osint.sh:105-256,
// PAR-03): clone every company repo into an isolated workspace tmp dir
// (sha256-named), run the titus + trufflehog secret-scan pair over the clones
// (cfg.OSINT.GitHub.SecretsEngine defaults to "hybrid" — and every value other than
// "noseyparker" runs this same pair), merge the per-repo scan output into
// osint/github_company_secrets.json (bash-parity human artefact), and emit REDACTED
// OSINTFindingRecords. Previously only enumerepo ran — no clone, no secret scan, no
// github_company_secrets.json.
//
// noseyparker is the sole non-default engine and is DEFERRED to Phase 14 (absent
// from tools.lock this phase). SecretsEngine=="noseyparker" logs a "deferred — using
// titus" note and falls back to the titus + trufflehog pair, which covers the ≥95%
// recon/all path.
//
// The repo list is written to inputs/github_repos.txt as a SINGLE-WRITER
// artefact (D-O5) — one URL per line — which GitHubLeaksTask reads via its
// DependsOn edge. Discovered repos are emitted as informational OSINTFindingRecords.
//
// KEY GATE (D-O8): reads cfg.Paths.GitHubTokens (the v1 $GITHUB_TOKENS file).
// Empty path / empty file → logged Info (naming the var, not the value) +
// StatusSkipped (logged-never-silent). Without a token the whole task skips
// cleanly, so a tokenless run is never broken.
//
// SECRET HANDLING (XCUT-07 / T-13-06-01/02): the GitHub token is written to a
// 0600 temp file and passed via enumerepo's -token-file flag (v1 osint.sh:80-85)
// so it is NEVER placed on argv or in a log line; the temp file is removed after
// the run. Every leaked secret surfaced by titus/trufflehog is registered with
// the log Redactor BEFORE any log line, scrubbed from the human artefact, and
// emitted to the findings stream ONLY as ValueRedacted="***" — the raw value
// NEVER reaches the JSONL findings stream or a log.
//
// SEEDING (D-O1): company-org-seeded, no DependsOn edges.
// FAILURE POLICY (D-O8): best_effort throughout — a missing tool / clone failure
// / scan error logs a warning and continues; the task returns StatusDone with the
// count of secrets found. It never aborts the osint pipeline.
//
// FOUND-10: enumerepo/titus/trufflehog run through app.Tools (the Runner seam);
// only `git clone` uses a direct, timeout-bounded exec.CommandContext behind the
// githubReposGitClone package var (git is a base system dependency, not a
// tools.lock recon binary — this file is on the FOUND-10 allowlist alongside the
// other repo-clone/stdin tool wrappers).
//
// Source: .planning/phases/07-osint-e2e/07-03-PLAN.md Task 2;
//
//	.planning/phases/13-domain-parity/13-06-PLAN.md Task 1 (secret-scan restore).
package osint

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

// githubReposCloneTimeout bounds a single `git clone` invocation. Company repos
// can be large (bash does a full clone so titus --git can walk history), so the
// ceiling is generous; a hung/auth-prompting clone is still killed.
const githubReposCloneTimeout = 300 * time.Second

// githubReposGitClone clones url into dest (bash: git clone <url> <dest>,
// osint.sh:110). It is the FOUND-10-allowlisted subprocess seam for this file:
// the name-keyed Backend/Runner registry runs tools.lock recon binaries, not
// `git` (a base system dependency used here to fetch untrusted third-party repos
// into an isolated workspace tmp dir for read-only scanning — T-13-06-04). The
// var is overridable so hermetic tests inject a fake clone. GIT_TERMINAL_PROMPT=0
// makes an auth-required clone fail fast instead of hanging on an interactive
// credential prompt.
var githubReposGitClone = func(ctx context.Context, url, dest string) error {
	// WR-13-04: validate the clone target BEFORE doing any work. Reject anything
	// that is not an http(s)/git clone URL so a value beginning with "-" (enumerepo
	// schema drift or plaintext-fallback garbage) can never be consumed by git as
	// an option (git option-injection, e.g. --upload-pack=…, or an "ext::"
	// transport → RCE where enabled).
	if !(strings.HasPrefix(url, "https://") || strings.HasPrefix(url, "http://") ||
		strings.HasPrefix(url, "git@")) {
		return fmt.Errorf("refusing to clone non-URL %q", url)
	}
	bin, err := exec.LookPath("git")
	if err != nil {
		return err // git not installed — caller degrades best-effort
	}
	cmdCtx, cancel := context.WithTimeout(ctx, githubReposCloneTimeout)
	defer cancel()
	// protocol.ext.allow=never disables git's ext:: transport; "--" ends option
	// parsing so the validated URL is always treated as a positional argument.
	//nolint:gosec // bin resolved via LookPath; url validated as http(s)/git URL above; "--" separates it from options; dest is workspace tmp
	cmd := exec.CommandContext(cmdCtx, bin, "-c", "protocol.ext.allow=never", "clone", "--", url, dest)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	return cmd.Run()
}

// GitHubReposTask runs enumerepo + the company-repo secret scan for OSINT-05 /
// PAR-03 (key-gated, feeds github_leaks).
type GitHubReposTask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (t *GitHubReposTask) Name() string { return "osint.github_repos" }

// Module returns the owning module group.
func (t *GitHubReposTask) Module() string { return "osint" }

// Description returns a human-readable one-line description.
func (t *GitHubReposTask) Description() string {
	return "GitHub org repo enumeration + secret scan (enumerepo + titus/trufflehog, OSINT-05/PAR-03)"
}

// Enabled reports whether GitHub repo enumeration is configured.
func (t *GitHubReposTask) Enabled(cfg *config.Config) bool {
	return cfg.OSINT.GitHub.Enabled
}

// DependsOn returns nil — enumerepo is the DAG root for the leak scan; it is
// company-org-seeded (D-O1) with no upstream edges of its own.
func (t *GitHubReposTask) DependsOn() []string { return nil }

// Run executes enumerepo over the company org, writes the repo list, then runs
// the full clone → titus + trufflehog → merged github_company_secrets.json
// secret pipeline.
//
// Steps:
//  1. Derive + validate the root domain → company name.
//  2. Key gate (D-O8): require a non-empty cfg.Paths.GitHubTokens file.
//  3. Write a 0600 temp token file; run enumerepo -token-file -usernames -o.
//  4. Parse the enumerepo output into a repo URL list.
//  5. Write inputs/github_repos.txt (single-writer artefact, feeds leaks).
//  6. Emit informational repo records; write staging JSONL.
//  7. Secret scan: clone → titus (+ noseyparker→titus deferral) + trufflehog →
//     osint/github_company_secrets.json + REDACTED findings.github_secrets.jsonl.
func (t *GitHubReposTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	root := rootDomain(app)
	if root == "" {
		if app.Log != nil {
			app.Log.Info("osint.github_repos: no valid root domain — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}
	company := companyName(root)

	// Step 2: GITHUB_TOKEN key gate (D-O8, logged-never-silent).
	token, ok := readGitHubToken(app)
	if !ok {
		if app.Log != nil {
			app.Log.Info("osint.github_repos: no GITHUB_TOKEN (cfg.paths.github_tokens) — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("osint.github_repos: mkdir inputs/: %w", err)
	}

	// Step 3: write a 0600 temp token file (T-13-06-01 — token off argv).
	tokenFile, err := writeTokenFile(token)
	if err != nil {
		if app.Log != nil {
			app.Log.Debug("osint.github_repos: write token file failed (best_effort)", "err", err)
		}
		return task.Result{Status: task.StatusDone, Stats: map[string]int{"repos": 0}}, nil
	}
	defer os.Remove(tokenFile) //nolint:errcheck

	usernamesFile := filepath.Join(inputsDir, "github_company_name.txt")
	if wErr := os.WriteFile(usernamesFile, []byte(company+"\n"), 0o644); wErr != nil { //nolint:gosec
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("osint.github_repos: write usernames file: %w", wErr)
	}
	enumOut := filepath.Join(inputsDir, "company_repos.json")

	// v1 arg vector (osint.sh:83): -token-file <f> -usernames <file> -o <out>.
	args := []string{"-token-file", tokenFile, "-usernames", usernamesFile, "-o", enumOut}
	if _, err := app.Tools.Run(ctx, "enumerepo", args); err != nil {
		if app.Log != nil {
			app.Log.Debug("osint.github_repos: enumerepo run failed (best_effort)", "err", err)
		}
		// Fall through — enumerepo may have written partial output.
	}

	// Step 4: parse the enumerepo output into a repo URL list.
	repos := parseEnumerepoOutput(enumOut)

	// Step 5: write inputs/github_repos.txt — the SINGLE-WRITER artefact that
	// GitHubLeaksTask consumes (D-O5 / D-O10 fold).
	reposListPath := filepath.Join(inputsDir, "github_repos.txt")
	if len(repos) > 0 {
		if wErr := os.WriteFile(reposListPath,
			[]byte(strings.Join(repos, "\n")+"\n"), 0o644); wErr != nil && app.Log != nil { //nolint:gosec
			app.Log.Debug("osint.github_repos: write github_repos.txt failed", "err", wErr)
		}
	}

	// Step 6: informational records (repo URLs are non-secret OSINT output).
	var records []OSINTFindingRecord
	for _, r := range repos {
		records = append(records, OSINTFindingRecord{
			Severity:    "informational",
			Class:       "osint",
			Source:      "github_repos",
			Category:    "repo",
			PoCRedacted: r,
		})
	}
	writeOSINTStaging(app, inputsDir, "findings.github_repos.jsonl", records)

	// Step 7: full company-repo secret scan (PAR-03 / 13-06). Best-effort — a
	// missing tool / clone failure never breaks the osint pipeline.
	secrets := t.scanCompanyRepos(ctx, app, repos)

	if app.Log != nil {
		app.Log.Info("osint.github_repos: completed", "repos", len(repos), "secrets", secrets)
	}
	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"repos": len(repos), "secrets": secrets},
	}, nil
}

// scanCompanyRepos performs the heavy bash github_repos secret pipeline
// (osint.sh:105-256) over the enumerated repo URLs: clone each repo, run the titus +
// trufflehog pair (the cfg SecretsEngine default "hybrid" — and any value other than
// "noseyparker" — runs this pair; noseyparker is deferred to Phase 14), merge the
// per-repo scan output into osint/github_company_secrets.json (bash-parity human
// artefact), and emit REDACTED findings. Returns the count of secrets surfaced.
// Every step is best-effort (D-O8).
func (t *GitHubReposTask) scanCompanyRepos(ctx context.Context, app *appctx.AppContext, urls []string) int {
	if len(urls) == 0 {
		return 0
	}
	cfg := app.Cfg
	threads := 10 // INTERLACE_THREADS analog (bash default)
	if cfg != nil && cfg.OSINT.GitHub.Threads > 0 {
		threads = cfg.OSINT.GitHub.Threads
	}

	tmpRoot := filepath.Join(app.Target.WorkDir, ".tmp")
	cloneRoot := filepath.Join(tmpRoot, "github_repos")
	githubDir := filepath.Join(tmpRoot, "github")
	if err := os.MkdirAll(cloneRoot, 0o750); err != nil {
		if app.Log != nil {
			app.Log.Debug("osint.github_repos: mkdir clone tmp failed (best_effort)", "err", err)
		}
		return 0
	}
	if err := os.MkdirAll(githubDir, 0o750); err != nil {
		if app.Log != nil {
			app.Log.Debug("osint.github_repos: mkdir scan tmp failed (best_effort)", "err", err)
		}
		return 0
	}
	// Free the heavy clones after scanning (the small JSON scan outputs in
	// githubDir are what the merge reads).
	defer os.RemoveAll(cloneRoot) //nolint:errcheck
	// IN-13-04: the per-repo titus/trufflehog scan outputs in githubDir hold RAW
	// (unscrubbed) secret values at 0600. Remove the whole scan-tmp dir on return so
	// they do not linger in .tmp/github after the run (the merged artefact scrubs
	// values to "***", but these upstream files do not). Deferred → fires at function
	// return, AFTER mergeSecretOutputs (the return expression below) has read them.
	defer os.RemoveAll(githubDir) //nolint:errcheck

	// Step A: clone all repos (bounded concurrency, sha256-named dirs). Each
	// goroutine writes its own index — no shared mutable state.
	cloned := make([]string, len(urls)) // cloned[i] = dest dir on success, else ""
	githubReposBounded(threads, len(urls), func(i int) {
		dest := filepath.Join(cloneRoot, githubReposSHA256(urls[i]))
		if err := githubReposGitClone(ctx, urls[i], dest); err != nil {
			if app.Log != nil {
				app.Log.Debug("osint.github_repos: git clone failed (best_effort)", "err", err)
			}
			return
		}
		cloned[i] = dest
	})

	// Step B: secrets-engine selection. The cfg SecretsEngine default is "hybrid",
	// which — like every value other than "noseyparker" — runs the titus + trufflehog
	// pair below. noseyparker is DEFERRED to Phase 14 (not in tools.lock); a
	// "noseyparker" selection logs a deferral note and falls back to that pair.
	if cfg != nil && strings.EqualFold(strings.TrimSpace(cfg.OSINT.GitHub.SecretsEngine), "noseyparker") && app.Log != nil {
		app.Log.Info("osint.github_repos: noseyparker deferred to Phase 14 — using titus")
	}

	// Step C: titus scan over each cloned repo dir (best-effort).
	t.runTitusScan(ctx, app, urls, cloned, githubDir)

	// Step D: trufflehog enrichment over each repo URL (all engines, best-effort).
	t.runTrufflehogScan(ctx, app, urls, githubDir)

	// Step E: merge per-repo scan outputs → github_company_secrets.json + findings.
	return t.mergeSecretOutputs(app, githubDir)
}

// runTitusScan runs `titus scan --format json [--git] [--validate] <repoDir>`
// over each cloned repo (bash osint.sh:190-215). titus stdout (per-repo JSON) is
// captured and written to githubDir/titus_<h>.json. Best-effort: a missing titus
// binary logs a single warning; a per-repo error is skipped.
func (t *GitHubReposTask) runTitusScan(ctx context.Context, app *appctx.AppContext, urls, cloned []string, githubDir string) {
	if !githubReposToolAvailable(app, "titus") {
		if app.Log != nil {
			app.Log.Warn("osint.github_repos: titus not found — skipping secret scan (best_effort)")
		}
		return
	}
	base := []string{"scan", "--format", "json"}
	if app.Cfg != nil && app.Cfg.OSINT.GitHub.ScanGitHistory {
		base = append(base, "--git")
	}
	if app.Cfg != nil && app.Cfg.OSINT.GitHub.ValidateSecrets {
		base = append(base, "--validate")
	}
	threads := githubReposThreads(app)
	githubReposBounded(threads, len(cloned), func(i int) {
		dir := cloned[i]
		if dir == "" {
			return
		}
		scanArgs := append(append([]string(nil), base...), dir)
		res, err := app.Tools.Run(ctx, "titus", scanArgs)
		if err != nil || res == nil {
			if app.Log != nil {
				app.Log.Debug("osint.github_repos: titus scan failed (best_effort)", "err", err)
			}
			return
		}
		if len(bytes.TrimSpace(res.Stdout)) == 0 {
			return
		}
		out := filepath.Join(githubDir, "titus_"+githubReposSHA256(urls[i])+".json")
		if wErr := os.WriteFile(out, res.Stdout, 0o600); wErr != nil && app.Log != nil {
			app.Log.Debug("osint.github_repos: write titus output failed", "err", wErr)
		}
	})
}

// runTrufflehogScan runs `trufflehog git <url> -j` over each repo URL (bash
// osint.sh:220-240, kept for all engines). Best-effort — a missing binary /
// per-repo error is skipped.
func (t *GitHubReposTask) runTrufflehogScan(ctx context.Context, app *appctx.AppContext, urls []string, githubDir string) {
	if !githubReposToolAvailable(app, "trufflehog") {
		return
	}
	threads := githubReposThreads(app)
	githubReposBounded(threads, len(urls), func(i int) {
		res, err := app.Tools.Run(ctx, "trufflehog", []string{"git", urls[i], "-j"})
		if err != nil || res == nil {
			if app.Log != nil {
				app.Log.Debug("osint.github_repos: trufflehog failed (best_effort)", "err", err)
			}
			return
		}
		if len(bytes.TrimSpace(res.Stdout)) == 0 {
			return
		}
		out := filepath.Join(githubDir, "th_"+githubReposSHA256(urls[i]))
		if wErr := os.WriteFile(out, res.Stdout, 0o600); wErr != nil && app.Log != nil {
			app.Log.Debug("osint.github_repos: write trufflehog output failed", "err", wErr)
		}
	})
}

// mergeSecretOutputs reads every per-repo scan output in githubDir (bash: cat
// .tmp/github/*), writes the merged native output to
// osint/github_company_secrets.json (bash-parity human artefact, with raw secret
// VALUES scrubbed to "***" — locators/structure preserved), and emits one
// REDACTED OSINTFindingRecord per surfaced secret. Every raw secret is registered
// with the log Redactor BEFORE any log line or file write (XCUT-07 L2). Returns
// the number of secret findings.
func (t *GitHubReposTask) mergeSecretOutputs(app *appctx.AppContext, githubDir string) int {
	entries, err := os.ReadDir(githubDir)
	if err != nil {
		return 0
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		return 0
	}
	sort.Strings(names) // deterministic merge order

	var merged [][]byte
	var records []OSINTFindingRecord
	var rawSecrets []string
	for _, name := range names {
		data, rErr := os.ReadFile(filepath.Join(githubDir, name)) //nolint:gosec // within WorkDir
		if rErr != nil {
			continue
		}
		trimmed := bytes.TrimSpace(data)
		if len(trimmed) == 0 {
			continue
		}
		merged = append(merged, trimmed)
		for _, s := range githubReposExtractSecrets(data) {
			// XCUT-07 L2: register every raw secret BEFORE any log / file write.
			for _, raw := range s.raws {
				registerSecret(app.Log, raw)
				rawSecrets = append(rawSecrets, raw)
			}
			records = append(records, OSINTFindingRecord{
				Severity:      "high",
				Confidence:    "medium",
				Class:         "osint",
				Source:        "github_repos",
				Category:      "leaked-secret",
				ValueRedacted: "***", // L3: raw secret NEVER propagated to the JSONL
				PoCRedacted:   s.locator,
			})
		}
	}
	if len(merged) == 0 {
		return 0
	}

	// bash-parity human artefact osint/github_company_secrets.json — the native
	// titus/trufflehog JSON with raw secret VALUES scrubbed to "***" (the
	// locators/structure a hunter reads are preserved). 0600 — the file still
	// names findings. The JSONL findings stream below is fully redacted
	// (XCUT-07 / T-13-06-02).
	osintDir := filepath.Join(app.Target.WorkDir, "osint")
	if mErr := os.MkdirAll(osintDir, 0o755); mErr != nil && app.Log != nil {
		app.Log.Debug("osint.github_repos: mkdir osint/ failed (best_effort)", "err", mErr)
	}
	body := bytes.Join(merged, []byte("\n"))
	for _, raw := range rawSecrets {
		body = bytes.ReplaceAll(body, []byte(raw), []byte("***"))
	}
	body = append(body, '\n')
	outPath := filepath.Join(osintDir, "github_company_secrets.json")
	if wErr := os.WriteFile(outPath, body, 0o600); wErr != nil && app.Log != nil {
		app.Log.Debug("osint.github_repos: write github_company_secrets.json failed", "err", wErr)
	}

	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	writeOSINTStaging(app, inputsDir, "findings.github_secrets.jsonl", records)
	return len(records)
}

// githubRepoSecret is a (raws, locator) record extracted from a titus/trufflehog
// per-repo scan output. raws are the raw secret values (registered with the
// Redactor, then DROPPED); only the non-secret locator + ValueRedacted="***"
// reach the findings stream.
type githubRepoSecret struct {
	raws    []string
	locator string
}

// githubReposSecretKeys are the (case-insensitive) JSON keys whose STRING value
// is treated as a raw secret (registered + scrubbed). Kept specific to avoid
// over-scrubbing generic fields.
var githubReposSecretKeys = map[string]struct{}{
	"secret": {}, "match": {}, "raw": {}, "rawv2": {}, "redacted": {},
}

// githubReposLocatorKeys are the (case-insensitive) JSON keys whose value forms
// the non-secret human-readable locator (repo/file/line/detector/rule).
var githubReposLocatorKeys = map[string]struct{}{
	"detector": {}, "detectorname": {}, "rule": {}, "ruleid": {},
	"file": {}, "path": {}, "repository": {}, "repo": {}, "line": {},
	"commit": {}, "description": {},
}

// githubReposExtractSecrets parses a per-repo titus/trufflehog scan output — a
// JSON array of finding objects, a single JSON object, or JSONL (one object per
// line) — into (raw, locator) records. It is deliberately schema-tolerant: titus's
// exact output shape is not pinned this phase, so it harvests any value under a
// known secret-bearing key (registered then dropped) and any non-secret locator
// key (mirrors the defensive ghleaks/trufflehog parsers in github_leaks.go).
func githubReposExtractSecrets(data []byte) []githubRepoSecret {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil
	}
	var out []githubRepoSecret
	add := func(node interface{}) {
		raws, locator := githubReposWalkRecord(node)
		if len(raws) == 0 && locator == "" {
			return
		}
		out = append(out, githubRepoSecret{raws: raws, locator: locator})
	}

	// Try a JSON array of records first.
	var arr []interface{}
	if err := json.Unmarshal(trimmed, &arr); err == nil {
		for _, el := range arr {
			add(el)
		}
		return out
	}
	// Try a single JSON object.
	var obj map[string]interface{}
	if err := json.Unmarshal(trimmed, &obj); err == nil {
		add(obj)
		return out
	}
	// Fall back to JSONL (one object per line — trufflehog -j).
	sc := bufio.NewScanner(bytes.NewReader(trimmed))
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var rec map[string]interface{}
		if err := json.Unmarshal(line, &rec); err == nil {
			add(rec)
		}
	}
	return out
}

// githubReposWalkRecord recursively collects raw secret values + locator
// fragments from one decoded finding record. A secret-keyed field is harvested
// (string only) and NOT recursed into, so a secret nested under a secret key is
// never mined for locators. Only whitelisted locator keys contribute to the
// locator; arbitrary strings are not harvested (they could embed a secret).
func githubReposWalkRecord(node interface{}) ([]string, string) {
	var raws []string
	var locParts []string
	seen := map[string]struct{}{}
	addLoc := func(s string) {
		if s == "" {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		locParts = append(locParts, s)
	}
	var walk func(interface{})
	walk = func(n interface{}) {
		switch v := n.(type) {
		case map[string]interface{}:
			for k, child := range v {
				lk := strings.ToLower(k)
				if _, ok := githubReposSecretKeys[lk]; ok {
					if s, isStr := child.(string); isStr && s != "" {
						raws = append(raws, s)
					}
					continue // never recurse into a secret-bearing field
				}
				if _, ok := githubReposLocatorKeys[lk]; ok {
					switch cv := child.(type) {
					case string:
						addLoc(cv)
					case float64:
						addLoc(fmt.Sprintf("%v", cv))
					}
					continue
				}
				walk(child)
			}
		case []interface{}:
			for _, child := range v {
				walk(child)
			}
		}
	}
	walk(node)
	return raws, strings.Join(locParts, " ")
}

// githubReposToolAvailable reports whether toolName is registered in the Runner's
// tool registry (single presence check → one "not found" warning instead of a
// per-repo error).
func githubReposToolAvailable(app *appctx.AppContext, toolName string) bool {
	if app == nil || app.Tools == nil || app.Tools.Registry == nil {
		return false
	}
	_, ok := app.Tools.Registry.Lookup(toolName)
	return ok
}

// githubReposThreads returns the bounded-concurrency width (cfg.OSINT.GitHub.Threads,
// INTERLACE_THREADS analog; default 10).
func githubReposThreads(app *appctx.AppContext) int {
	if app != nil && app.Cfg != nil && app.Cfg.OSINT.GitHub.Threads > 0 {
		return app.Cfg.OSINT.GitHub.Threads
	}
	return 10
}

// githubReposBounded runs fn(0..n-1) with at most `threads` concurrent
// invocations (bash's _throttle_jobs INTERLACE_THREADS analog).
func githubReposBounded(threads, n int, fn func(i int)) {
	if n <= 0 {
		return
	}
	if threads < 1 {
		threads = 1
	}
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int) {
			defer wg.Done()
			defer func() { <-sem }()
			fn(idx)
		}(i)
	}
	wg.Wait()
}

// githubReposSHA256 returns the hex sha256 of s (bash: sha256sum | cut -d' ' -f1)
// — the collision-free per-repo directory / output-file name.
func githubReposSHA256(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// parseEnumerepoOutput extracts the deduped list of repo clone URLs from
// enumerepo's JSON output. enumerepo emits a JSON array of objects keyed by
// username, each carrying a "repos" array of repo metadata. We tolerate several
// shapes (object-keyed map, array of {repos:[{url|html_url|clone_url|full_name}]})
// and also fall back to plain-text lines (one repo per line).
func parseEnumerepoOutput(path string) []string {
	data, err := os.ReadFile(path) //nolint:gosec // within WorkDir
	if err != nil || len(strings.TrimSpace(string(data))) == 0 {
		return nil
	}
	seen := make(map[string]struct{})
	var out []string
	add := func(u string) {
		u = strings.TrimSpace(u)
		if u == "" {
			return
		}
		if _, ok := seen[u]; ok {
			return
		}
		seen[u] = struct{}{}
		out = append(out, u)
	}

	// WR-13-05: only fall back to plain-text parsing when the payload is NOT valid
	// JSON. enumerepo emits JSON; if it parses but collectRepoURLs recognizes no
	// repo keys (schema drift), an empty list is the correct result — shredding the
	// pretty-printed JSON into per-line "{"/"}" garbage would pollute the repo list,
	// the informational findings, and the git-clone seam (WR-13-04).
	var generic interface{}
	if jErr := json.Unmarshal(data, &generic); jErr == nil {
		collectRepoURLs(generic, add)
		return out
	}

	// Plain-text fallback: one repo URL / full_name per line (JSON parse failed).
	for _, line := range splitNonEmptyLines(data) {
		add(line)
	}
	return out
}

// collectRepoURLs walks a decoded enumerepo JSON tree, adding any repo URL or
// full_name leaf via add.
func collectRepoURLs(node interface{}, add func(string)) {
	switch v := node.(type) {
	case map[string]interface{}:
		for k, child := range v {
			switch strings.ToLower(k) {
			case "url", "html_url", "clone_url", "ssh_url", "full_name":
				if s, ok := child.(string); ok {
					add(s)
					continue
				}
			}
			collectRepoURLs(child, add)
		}
	case []interface{}:
		for _, child := range v {
			collectRepoURLs(child, add)
		}
	}
}

// init self-registers GitHubReposTask with the Default task registry.
func init() { task.Register(&GitHubReposTask{}) }

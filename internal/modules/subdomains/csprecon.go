// csprecon.go — SubCspreconTask: CSP-header subdomain discovery in the subs
// discovery stage (PAR-01, parity with bash sub_scraping's csprecon source).
//
// STAGING CONTRACT (doc.go): SubCspreconTask writes in-scope hostnames as PLAIN
// newline-delimited lines to inputs/resolved.csprecon.txt. It does NOT call
// app.Tree.Append — MergeStage(ctx, app, "resolved") is the single Tree.Append
// caller for the resolved stage.
//
// This task MIRRORS internal/modules/web/csprecon.go (CspreconTask) but for the
// subdomains package + resolved staging: the same `csprecon -s -l <file>` arg
// vector and the same extract/csp.Extract anchored in-scope filter (T-13-02-01 —
// reuse, no re-implement). It reuses the scraping gate (cfg.Subdomains.Scraping.
// Enabled) — csprecon is a scraping-class discovery source; no new config field.
//
// WIRING NOTE: this task self-registers via init() and is built into the DAG but
// remains UNSELECTED until 13-08 adds the "subdomains.csprecon" prefix to the
// discovery stage list (subs.go/composite.go/stub_subcommands.go). This plan does
// NOT edit any stage list; the unit test exercises Run directly.
//
// bash reference (modules/subdomains.sh:1222-1246, sub_scraping):
//
//	cat <probed hosts> | csprecon -s | sed 's/^\*\.//' | filter_in_scope_hosts "$domain" | sort -u
//
// The Backend/Runner seam has no stdin channel (doc.go / reverseip.go), so — like
// web/csprecon.go — the host list is passed via -l <file> instead of bash's stdin
// pipe. csprecon (edoardottt/csprecon) is a LocalBackend tool already in tools.lock.
//
// Source: .planning/phases/13-domain-parity/13-02-PLAN.md Task 1.
package subdomains

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
	"github.com/six2dez/reconftw/internal/extract/csp"
)

// SubCspreconTask discovers subdomains from Content-Security-Policy headers via
// csprecon, writing in-scope hostnames to inputs/resolved.csprecon.txt.
type SubCspreconTask struct{}

func (SubCspreconTask) Name() string        { return "subdomains.csprecon" }
func (SubCspreconTask) Module() string      { return "subdomains" }
func (SubCspreconTask) DependsOn() []string { return nil }

func (SubCspreconTask) Description() string {
	return "CSP-header subdomain discovery (csprecon)"
}

// Enabled reuses the scraping gate — csprecon is a scraping-class discovery
// source (parity with SubScrapingTask; no separate config field is introduced).
func (SubCspreconTask) Enabled(cfg *config.Config) bool {
	return cfg.Subdomains.Scraping.Enabled
}

// Run feeds the merged passive subdomain surface to csprecon, extracts in-scope
// hostnames from the CSP output via extract/csp.Extract, and writes them as plain
// lines to inputs/resolved.csprecon.txt for MergeStage.
//
// Aux best-effort posture: a csprecon tool error (binary absent, non-zero exit)
// OR an empty/absent input surface degrades to StatusDone with an empty staging
// file + a logged warning — never StatusErrored. The discovery stage is a
// best-effort augmentation; one flaky discovery source must not abort the run.
func (SubCspreconTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "csprecon"
	domain := app.Target.Domain

	// Input surface: the merged passive subdomain set (same list the sibling
	// resolve tasks read). csprecon probes each host's CSP header.
	inputFile := passiveMergedPath(app)
	hosts, err := readLines(inputFile)
	if err != nil || len(hosts) == 0 {
		if app.Log != nil {
			app.Log.Info("subdomains.csprecon: no passive.merged input — skipping")
		}
		return cspreconEmptyDone(app, toolName)
	}

	// The Runner has no stdin seam (doc.go), so mirror web/csprecon.go and pass
	// the host list via -l <file>. This scratch file (inputs/csprecon.hosts.txt)
	// is NOT a resolved.*.txt staging file, so MergeStage never reads it.
	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("subdomains.csprecon: mkdir inputs/: %w", err)
	}
	hostsFile := filepath.Join(inputsDir, "csprecon.hosts.txt")
	if err := os.WriteFile(hostsFile, []byte(strings.Join(hosts, "\n")+"\n"), 0o644); err != nil { //nolint:gosec
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("subdomains.csprecon: write hosts file: %w", err)
	}

	// csprecon -s (silent) -l <file>: verbatim mirror of web/csprecon.go's arg vector.
	res, execErr := app.Tools.Run(ctx, toolName, []string{"-s", "-l", hostsFile})
	if execErr != nil {
		// Aux best-effort degrade: log + empty staging, StatusDone (never abort).
		if app.Log != nil {
			app.Log.Warn("subdomains.csprecon: csprecon failed (non-fatal degrade)",
				"tool", toolName, "error", execErr.Error())
		}
		return cspreconEmptyDone(app, toolName)
	}

	var rawOutput []byte
	if res != nil {
		rawOutput = res.Stdout
	}

	// extract/csp.Extract applies the anchored domain-suffix in-scope filter
	// (T-13-02-01 mitigation — reuse, no re-implement). Source field is "csp".
	hostResults, _ := csp.Extract(rawOutput, domain)
	hostnames := make([]string, 0, len(hostResults))
	for _, r := range hostResults {
		if r.Subdomain != "" {
			hostnames = append(hostnames, r.Subdomain)
		}
	}

	stagingPath, werr := writeResolvedStagingFile(app, toolName, hostnames)
	if werr != nil {
		return task.Result{Status: task.StatusErrored}, werr
	}
	if app.Log != nil {
		app.Log.Debug("subdomains.csprecon: completed", "csprecon_hostnames", len(hostnames))
	}
	return task.Result{
		Status:  task.StatusDone,
		Outputs: []string{stagingPath},
		Stats:   map[string]int{"csprecon_hostnames": len(hostnames)},
	}, nil
}

// cspreconEmptyDone writes an empty resolved.csprecon.txt staging file and returns
// StatusDone — the aux best-effort no-input / tool-error posture (keeps MergeStage
// consuming a consistent set; a local FS write error stays fatal).
func cspreconEmptyDone(app *appctx.AppContext, toolName string) (task.Result, error) {
	stagingPath, werr := writeResolvedStagingFile(app, toolName, nil)
	if werr != nil {
		return task.Result{Status: task.StatusErrored}, werr
	}
	return task.Result{
		Status:  task.StatusDone,
		Outputs: []string{stagingPath},
		Stats:   map[string]int{"csprecon_hostnames": 0},
	}, nil
}

func init() { task.Register(SubCspreconTask{}) }

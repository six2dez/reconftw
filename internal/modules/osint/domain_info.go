// domain_info.go — DomainInfoTask: whois + DNS records + Scopify (OSINT-01 / PAR-03).
//
// DomainInfoTask runs whois on the root domain and dnsx for the NS/MX/TXT/SOA
// DNS record set (v1 modules/osint.sh:575 domain_info + mail_hygiene's TXT/DMARC
// records). Each record becomes an informational OSINTFindingRecord (D-O4) and
// is written to inputs/findings.domain_info.jsonl per the multi-writer staging
// contract (doc.go — D-O3). The raw whois text is preserved as the single-writer
// human file osint/domain_info_general.txt (D-O5).
//
// It then runs Scopify (v1 domain_info() osint.sh:606-607) over the registrable
// company name (the `unfurl format %r` analog, companyName) → osint/scopify.txt.
// This restored a PAR-03 gap: the Go task previously had no Scopify call, so no
// scopify.txt was produced. Scopify is a python-venv repo-clone tool invoked by
// name through app.Tools (mirroring the other python-venv osint tools) and, like
// bash, writes its report to STDOUT which we capture to the single-writer file.
//
// SEEDING (D-O1): root-domain-seeded — runs from app.Target.Domain alone, no URL
// corpus, no DependsOn edges, never bootstraps subs/web.
//
// FAILURE POLICY (D-O8, ARCH-09): best_effort. A tool failing / finding nothing
// logs Debug and returns StatusDone with findings:0 — the run COMPLETES.
//
// PD TOOLS (D-O7): dnsx args include -duc to avoid update-check hangs.
//
// THREAT MODEL (T-07-02-01): the domain string crosses into whois/dnsx argv via
// Backend.Run's []string arg-vector (never a shell string); rootDomain validates
// a registrable-domain shape before use.
//
// Source: .planning/phases/07-osint-e2e/07-02-PLAN.md Task 1.
package osint

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/core/task"
)

// DomainInfoTask runs whois + DNS records for OSINT-01.
type DomainInfoTask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (t *DomainInfoTask) Name() string { return "osint.domain_info" }

// Module returns the owning module group.
func (t *DomainInfoTask) Module() string { return "osint" }

// Description returns a human-readable one-line description.
func (t *DomainInfoTask) Description() string { return "whois + DNS records (OSINT-01)" }

// Enabled reports whether domain_info is configured.
func (t *DomainInfoTask) Enabled(cfg *config.Config) bool {
	return cfg.OSINT.DomainInfo.Enabled
}

// DependsOn returns nil — OSINT is root-domain-seeded (D-O1), no DAG edges.
func (t *DomainInfoTask) DependsOn() []string { return nil }

// dnsRecordTypes maps the dnsx record-type flag to the OSINTFindingRecord
// Category emitted for each matched record (v1 osint.sh:575 NS/MX/TXT/SOA).
var dnsRecordTypes = []struct {
	flag     string // dnsx flag
	category string // OSINTFindingRecord.Category
}{
	{"-ns", "dns-ns"},
	{"-mx", "dns-mx"},
	{"-txt", "dns-txt"},
	{"-soa", "dns-soa"},
}

// Run executes whois + dnsx record lookups + Scopify against the root domain.
//
// Steps:
//  1. Derive + validate the root domain from app.Target.
//  2. Run whois; preserve osint/domain_info_general.txt (D-O5); emit a whois record.
//  3. Run dnsx per record type with -duc (D-O7); emit one record per result.
//  4. Run Scopify over the company name → osint/scopify.txt (D-O5 single-writer).
//  5. Write inputs/findings.domain_info.jsonl (multi-writer staging).
func (t *DomainInfoTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	root := rootDomain(app)
	if root == "" {
		if app.Log != nil {
			app.Log.Info("osint.domain_info: no valid root domain — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("osint.domain_info: mkdir inputs/: %w", err)
	}
	osintDir := filepath.Join(app.Target.WorkDir, "osint")
	if err := os.MkdirAll(osintDir, 0o755); err != nil {
		if app.Log != nil {
			app.Log.Debug("osint.domain_info: mkdir osint/ failed (best_effort)", "err", err)
		}
	}

	var records []OSINTFindingRecord

	// Step 2: whois — raw text → osint/domain_info_general.txt (D-O5 single-writer).
	if res, err := app.Tools.Run(ctx, "whois", []string{root}); err != nil {
		if app.Log != nil {
			app.Log.Debug("osint.domain_info: whois run failed (best_effort)", "err", err)
		}
	} else if len(bytes.TrimSpace(res.Stdout)) > 0 {
		whoisFile := filepath.Join(osintDir, "domain_info_general.txt")
		if wErr := os.WriteFile(whoisFile, res.Stdout, 0o644); wErr != nil && app.Log != nil { //nolint:gosec
			app.Log.Debug("osint.domain_info: write domain_info_general.txt failed", "err", wErr)
		}
		records = append(records, OSINTFindingRecord{
			Severity: "informational",
			Class:    "osint",
			Source:   "domain_info",
			Category: "whois",
		})
	}

	// Step 3: dnsx per record type with -duc (D-O7).
	// dnsxRan records whether AT LEAST ONE dnsx lookup was dispatched, and
	// cancelled records an interrupted loop. Neither an absent dnsx nor a
	// cancelled run observed the domain, so neither may clear a previous run's
	// staging (F3 did-not-run — see writeOSINTStaging).
	dnsxRan := false
	cancelled := false
	for _, rt := range dnsRecordTypes {
		if ctx.Err() != nil {
			cancelled = true
			break
		}
		// v1 dnsx record lookup arg vector: dnsx -duc -silent -resp-only <type> -d <domain>
		args := []string{"-duc", "-silent", "-resp-only", rt.flag, "-d", root}
		res, err := app.Tools.Run(ctx, "dnsx", args)
		if err != nil {
			if app.Log != nil {
				app.Log.Debug("osint.domain_info: dnsx run failed (best_effort)",
					"type", rt.category, "err", err)
			}
			continue
		}
		dnsxRan = true
		for _, val := range splitNonEmptyLines(res.Stdout) {
			records = append(records, OSINTFindingRecord{
				Severity:    "informational",
				Class:       "osint",
				Source:      "domain_info",
				Category:    rt.category,
				PoCRedacted: val, // DNS record value (non-secret; informational, T-07-02-03 accept)
			})
		}
	}

	// Step 4: Scopify scope enumeration (v1 domain_info() osint.sh:606-607).
	t.runScopify(ctx, app, root, osintDir)

	// Step 5: write staging JSONL (multi-writer contract).
	// F3: a run that resolved no DNS record REMOVES the staging file rather than
	// republishing records the zone no longer serves.
	if dnsxRan && !cancelled {
		writeOSINTStaging(app, inputsDir, "findings.domain_info.jsonl", records)
	} else if app.Log != nil {
		app.Log.Debug("osint.domain_info: dnsx did not resolve the record types — staging preserved (F3 did-not-run)")
	}

	if app.Log != nil {
		app.Log.Info("osint.domain_info: completed", "findings", len(records))
	}
	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"findings": len(records)},
	}, nil
}

// runScopify runs Scopify over the registrable company name (v1 domain_info()
// osint.sh:606-607): `company_name=$(unfurl format %r <<< $domain)` then
// `scopify.py -c <company_name> > osint/scopify.txt`. company_name is derived via
// the in-package companyName helper (the `unfurl format %r` analog). Scopify
// writes its report to STDOUT, which we capture to the single-writer human file
// osint/scopify.txt (D-O5, matching bash's `> osint/scopify.txt`).
//
// Best_effort (D-O8): a missing tool / venv / empty output logs Debug and returns
// without disturbing the whois/dnsx path (the task never fails on Scopify).
func (t *DomainInfoTask) runScopify(ctx context.Context, app *appctx.AppContext, root, osintDir string) {
	company := companyName(root)
	if company == "" {
		return
	}
	// v1 arg vector (osint.sh:607): scopify.py -c <company_name>; report → STDOUT.
	res, err := app.Tools.Run(ctx, "Scopify", []string{"-c", company})
	if err != nil {
		if app.Log != nil {
			app.Log.Debug("osint.domain_info: Scopify run failed (best_effort)", "err", err)
		}
		return
	}
	if len(bytes.TrimSpace(res.Stdout)) == 0 {
		return
	}
	// D-O5 single-writer human file: osint/scopify.txt (bash `> osint/scopify.txt`).
	scopifyFile := filepath.Join(osintDir, "scopify.txt")
	if wErr := os.WriteFile(scopifyFile, res.Stdout, 0o644); wErr != nil && app.Log != nil { //nolint:gosec
		app.Log.Debug("osint.domain_info: write scopify.txt failed", "err", wErr)
	}
}

// init self-registers DomainInfoTask with the Default task registry.
func init() { task.Register(&DomainInfoTask{}) }

// -------------------------------------------------------------------------
// Shared osint helpers (defined here, used across Wave 2 osint Task files).
// -------------------------------------------------------------------------

// rootDomain derives the registrable root domain from app.Target. It rejects
// IP/CIDR targets (OSINT domain functions are domain-only — v1 guards with the
// IPv4 regex in osint.sh) and validates a registrable-domain shape before the
// value crosses into tool argv (T-07-02-01). Returns "" when unusable.
func rootDomain(app *appctx.AppContext) string {
	if app == nil || app.Target == nil {
		return ""
	}
	if app.Target.IsIP || app.Target.IsCIDR {
		return ""
	}
	d := strings.ToLower(strings.TrimSpace(app.Target.Domain))
	if d == "" {
		return ""
	}
	// Registrable-domain shape: at least one dot, no shell/whitespace metachars.
	if !strings.Contains(d, ".") {
		return ""
	}
	if strings.ContainsAny(d, " \t\r\n;|&$`<>(){}'\"\\") {
		return ""
	}
	return d
}

// splitNonEmptyLines returns each trimmed non-empty line of data.
func splitNonEmptyLines(data []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		out = append(out, line)
	}
	return out
}

// writeOSINTStaging marshals records and writes inputs/<fileName> through
// output.StageJSONL (the per-task staging file — doc.go contract). Errors are
// logged at Debug (best_effort).
//
// This is the SINGLE staging writer for all 20 osint producer files, so the F3
// run-isolation contract lives here for the whole package.
//
// F3 (phase 15): the write is UNCONDITIONAL. It used to return early when
// records was empty, so an osint task that RAN and found nothing left the
// previous run's staging file on disk and MergeOSINTFindings republished it — a
// leaked credential that has since been rotated, or a cloud bucket that has
// since been locked down, kept appearing in every later report as though this
// run had just found it. StageJSONL REMOVES the file instead.
//
// CALLER CONTRACT — only call this when the task actually RAN. A task that
// returned before invoking its tool, or whose tool is not installed, observed
// nothing and must not delete what a previous run observed. Most osint tasks
// satisfy this by returning early on a tool error; the ones whose per-item loops
// can fail for EVERY item guard the call with an explicit "did the tool run"
// flag. See internal/modules/vulns/staging.go for the same rule stated in full.
func writeOSINTStaging(app *appctx.AppContext, inputsDir, fileName string, records []OSINTFindingRecord) {
	var lines [][]byte
	for _, rec := range records {
		b, mErr := json.Marshal(rec)
		if mErr != nil {
			continue
		}
		lines = append(lines, b)
	}
	stagingPath := filepath.Join(inputsDir, fileName)
	if wErr := output.StageJSONL(stagingPath, lines); wErr != nil && app.Log != nil {
		app.Log.Debug("osint: staging write failed", "path", stagingPath, "err", wErr)
	}
}

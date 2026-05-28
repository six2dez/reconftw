// stub_subcommands.go — 12 stubbed v2 subcommand constructors per D-01 + D-02.
//
// Source: ADR 0002 §8.1 (subcommand inventory) + 03-CONTEXT.md D-01 / D-02.
//
// All 12 stubbed subcommands share the same shape — Use/Short/Long populate
// from the constants table below; RunE returns stubNotImplemented(cmd, phase, name).
// Phase 4-12 implementers replace the RunE body without touching the CLI plumbing.
//
// Subcommand inventory (12 stubbed + 3 working + 1 hidden = 16 subcommands total):
//
//	stubbed  (12):  recon, all, passive, subs, web, vulns, osint, zen, deep,
//	                monitor, report, mcp, migrate, install     — D-02 exit 64
//	working  (3):   version, health-check                       — D-04 fully working
//	hidden   (1):   kernel-demo                                 — W16 / ADR §0 D-07

package main

import "github.com/spf13/cobra"

// stubPhase carries the (Phase N, Phase Name) tuple used by the phase-pointer message.
type stubPhase struct {
	Phase int
	Name  string
}

// phasePointers maps a stubbed subcommand name → (Phase number, Phase name).
// Each entry sources from .planning/ROADMAP.md phase plan inventory.
//
// All 12 entries match the 12 stubbed subcommand names; lookup by `cmd.Name()`.
var phasePointers = map[string]stubPhase{
	"recon":   {4, "Subdomains E2E + Axiom Integration (recon composite)"},
	"all":     {9, "Composite Modes (all)"},
	"passive": {9, "Composite Modes (passive)"},
	"subs":    {4, "Subdomains E2E + Axiom Integration"},
	"web":     {5, "Web Pipeline E2E"},
	"vulns":   {6, "Vulnerability Scanning E2E"},
	"osint":   {7, "OSINT E2E"},
	"zen":     {9, "Composite Modes (zen)"},
	"deep":    {9, "Composite Modes (deep)"},
	"monitor": {10, "Monitor Mode + Reporting + Notifications"},
	"report":  {10, "Monitor Mode + Reporting + Notifications"},
	"mcp":     {8, "MCP Server"},
	"migrate": {11, "Installer + Cross-Platform + Docker"},
	"install": {11, "Installer + Cross-Platform + Docker"},
}

// newStubCmd is the shared constructor for all stubbed v2 subcommands.
// Use/Short are populated from the caller; the RunE looks up phase pointer
// from phasePointers and returns the D-02 phase-pointer error.
func newStubCmd(use, short string) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: short,
		RunE: func(cmd *cobra.Command, args []string) error {
			p := phasePointers[cmd.Name()]
			return stubNotImplemented(cmd, p.Phase, p.Name)
		},
	}
}

// newReconCmd — Phase 4 (Subdomains E2E + Axiom Integration). Stubbed per D-02.
// V2 entry point for the `recon` composite mode (passive subs + web probe + OSINT).
func newReconCmd() *cobra.Command {
	return newStubCmd("recon", "Run recon mode (passive subs + web probe + web analysis + OSINT)")
}

// newAllCmd — Phase 9 (Composite Modes). Stubbed per D-02.
func newAllCmd() *cobra.Command {
	return newStubCmd("all", "Run all modules: recon + active subs + brute + permut + vulns")
}

// newPassiveCmd — Phase 9 (Composite Modes). Stubbed per D-02.
func newPassiveCmd() *cobra.Command {
	return newStubCmd("passive", "Run passive-only modules (no active probes)")
}

// newSubsCmd — Phase 4 (Subdomains E2E). Stubbed per D-02.
func newSubsCmd() *cobra.Command {
	return newStubCmd("subs", "Run subdomain enumeration (passive + active + permut + takeover)")
}

// newWebCmd — Phase 5 (Web Pipeline E2E). Stubbed per D-02.
func newWebCmd() *cobra.Command {
	return newStubCmd("web", "Run web probing + analysis (httpx + screenshots + nuclei + fuzz + JS)")
}

// newVulnsCmd — Phase 6 (Vulnerability Scanning E2E). Stubbed per D-02.
func newVulnsCmd() *cobra.Command {
	return newStubCmd("vulns", "Run vulnerability scanning (XSS, SQLi, SSRF, LFI, SSTI, etc.)")
}

// newOSINTCmd — Phase 7 (OSINT E2E). Stubbed per D-02.
func newOSINTCmd() *cobra.Command {
	return newStubCmd("osint", "Run OSINT collection (dorks, GitHub leaks, emails, cloud, etc.)")
}

// newZenCmd — Phase 9 (Composite Modes). Stubbed per D-02.
func newZenCmd() *cobra.Command {
	return newStubCmd("zen", "Run zen mode (minimal noise — passive only + safe probes)")
}

// newDeepCmd — Phase 9 (Composite Modes). Stubbed per D-02.
func newDeepCmd() *cobra.Command {
	return newStubCmd("deep", "Run deep mode (all + recursive subdomain enum + advanced fuzz)")
}

// newMonitorCmd — Phase 10 (Monitor + Reporting). Stubbed per D-02.
func newMonitorCmd() *cobra.Command {
	return newStubCmd("monitor", "Run monitor loop (periodic re-scan with diff notifications)")
}

// newReportCmd — Phase 10 (Monitor + Reporting). Stubbed per D-02.
func newReportCmd() *cobra.Command {
	return newStubCmd("report", "Generate report from prior scan workspace")
}

// newMCPCmd — Phase 8 (MCP Server). Stubbed per D-02.
func newMCPCmd() *cobra.Command {
	return newStubCmd("mcp", "Run MCP server (Model Context Protocol — SSE multiplexing)")
}

// newMigrateCmd — Phase 11 (Installer + Cross-Platform). Stubbed per D-02.
func newMigrateCmd() *cobra.Command {
	return newStubCmd("migrate", "Migrate v1 reconftw.cfg to v2 reconftw.toml")
}

// newInstallCmd — Phase 11 (Installer + Cross-Platform). Stubbed per D-02.
func newInstallCmd() *cobra.Command {
	return newStubCmd("install", "Install or update reconFTW tool dependencies (per tools.lock)")
}

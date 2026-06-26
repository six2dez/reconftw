// profiles_test.go — unit tests for ApplyZenProfile / ApplyDeepProfile.
//
// External test package per project convention (coverage_test.go pattern).
// Tests are exhaustive: one assertion per field in the profiles, plus a
// stacking test verifying D-03 (zen over deep — zen wins on conflicts).
package config_test

import (
	"testing"

	"github.com/six2dez/reconftw/internal/core/config"
)

// TestApplyZenProfile verifies every field set by ApplyZenProfile against the
// values specified in RESEARCH.md Q2 "applyZenProfile" table.
func TestApplyZenProfile(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	config.ApplyZenProfile(cfg)

	// Advanced profile
	if cfg.Advanced.PerfProfile != "low" {
		t.Errorf("zen PerfProfile = %q, want %q", cfg.Advanced.PerfProfile, "low")
	}

	// Concurrency
	if cfg.Concurrency.MaxJobs != 2 {
		t.Errorf("zen MaxJobs = %d, want 2", cfg.Concurrency.MaxJobs)
	}

	// Web rate limits
	if cfg.Web.Probe.RateLimit != 30 {
		t.Errorf("zen Web.Probe.RateLimit = %d, want 30", cfg.Web.Probe.RateLimit)
	}
	if cfg.Web.Nuclei.RateLimit != 15 {
		t.Errorf("zen Web.Nuclei.RateLimit = %d, want 15", cfg.Web.Nuclei.RateLimit)
	}
	if cfg.Web.Fuzz.RateLimit != 10 {
		t.Errorf("zen Web.Fuzz.RateLimit = %d, want 10", cfg.Web.Fuzz.RateLimit)
	}
	if cfg.Web.Fuzz.Threads != 5 {
		t.Errorf("zen Web.Fuzz.Threads = %d, want 5", cfg.Web.Fuzz.Threads)
	}

	// Subdomains — disable noisy active sources
	if cfg.Subdomains.Brute.Enabled {
		t.Error("zen must disable Subdomains.Brute.Enabled")
	}
	if cfg.Subdomains.Permut.Enabled {
		t.Error("zen must disable Subdomains.Permut.Enabled")
	}

	// Web active scanning
	if cfg.Web.Portscan.ActiveEnabled {
		t.Error("zen must disable Web.Portscan.ActiveEnabled")
	}

	// Vulns — zen never runs vulns
	if cfg.Vulns.Enabled {
		t.Error("zen must disable Vulns.Enabled")
	}

	// Output — "be quiet, period" per CONTEXT.md
	if cfg.Output.Verbosity != 0 {
		t.Errorf("zen Output.Verbosity = %d, want 0", cfg.Output.Verbosity)
	}

	// OSINT — disable gato (active/credentialed GitHub API calls)
	if cfg.OSINT.GitHub.ActionsAudit.Enabled {
		t.Error("zen must disable OSINT.GitHub.ActionsAudit.Enabled (gato is active/credentialed)")
	}
}

// TestApplyDeepProfile verifies every field set by ApplyDeepProfile against the
// values specified in RESEARCH.md Q2 "applyDeepProfile" table.
func TestApplyDeepProfile(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	config.ApplyDeepProfile(cfg)

	// Advanced.Deep is the primary gate
	if !cfg.Advanced.Deep {
		t.Error("deep must set Advanced.Deep = true")
	}

	// Recursive subdomain enumeration
	if !cfg.Subdomains.Recursive.BruteEnabled {
		t.Error("deep must enable Subdomains.Recursive.BruteEnabled")
	}
	if !cfg.Subdomains.Recursive.PassiveEnabled {
		t.Error("deep must enable Subdomains.Recursive.PassiveEnabled")
	}

	// Permutation wordlist mode
	if cfg.Subdomains.Permut.WordlistMode != "full" {
		t.Errorf("deep Subdomains.Permut.WordlistMode = %q, want %q", cfg.Subdomains.Permut.WordlistMode, "full")
	}

	// Deeper fuzz recursion
	if cfg.Web.Fuzz.RecursionDepth != 4 {
		t.Errorf("deep Web.Fuzz.RecursionDepth = %d, want 4", cfg.Web.Fuzz.RecursionDepth)
	}

	// Extended port scan
	if cfg.Web.Portscan.Naabu.Ports != "--top-ports 10000" {
		t.Errorf("deep Web.Portscan.Naabu.Ports = %q, want %q",
			cfg.Web.Portscan.Naabu.Ports, "--top-ports 10000")
	}
}

// TestZenDeepStackable verifies D-03: when both ApplyDeepProfile and ApplyZenProfile
// are applied (in that order), zen wins on conflicting fields.
//
// Specifically:
//   - cfg.Vulns.Enabled must be false (zen disables it; deep does not enable it)
//   - cfg.Advanced.Deep must still be true (deep's structural change is preserved;
//     zen only restricts rate/noise — it does not reset Advanced.Deep)
func TestZenDeepStackable(t *testing.T) {
	t.Parallel()

	cfg := config.Defaults()
	config.ApplyDeepProfile(cfg) // apply deep first
	config.ApplyZenProfile(cfg)  // apply zen second — zen wins on conflicts (D-03)

	// zen wins: Vulns must be disabled
	if cfg.Vulns.Enabled {
		t.Error("stacked deep+zen: zen must override Vulns.Enabled to false")
	}

	// deep's structural change preserved: Advanced.Deep stays true
	if !cfg.Advanced.Deep {
		t.Error("stacked deep+zen: Advanced.Deep must remain true (deep set it; zen does not reset it)")
	}

	// zen wins: Subdomains.Brute must be disabled
	if cfg.Subdomains.Brute.Enabled {
		t.Error("stacked deep+zen: zen must override Subdomains.Brute.Enabled to false")
	}

	// zen wins: MaxJobs must be 2
	if cfg.Concurrency.MaxJobs != 2 {
		t.Errorf("stacked deep+zen: zen MaxJobs = %d, want 2", cfg.Concurrency.MaxJobs)
	}

	// deep's structural change preserved: RecursionDepth stays 4
	if cfg.Web.Fuzz.RecursionDepth != 4 {
		t.Errorf("stacked deep+zen: Web.Fuzz.RecursionDepth = %d, want 4 (set by deep, not overridden by zen)",
			cfg.Web.Fuzz.RecursionDepth)
	}
}

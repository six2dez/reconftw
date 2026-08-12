// profiles.go — in-memory config transforms for zen and deep modes.
//
// Applied after config.Load, before BootReconApp (D-02/D-03).
// Pure functions; no side effects; stackable (deep+zen = apply both in sequence;
// zen applied last wins on conflicts per D-03).
//
// ApplyZenProfile: stealth/minimal-noise profile (zen subcommand, MODE-04).
// ApplyDeepProfile: extended brute + permutations + deeper scans (deep subcommand, MODE-05).
//
// Security guarantee (T-09-01-01/T-09-01-03): these are pure in-memory transforms.
// No I/O, no exec. Applied only inside BootReconApp after config.Load and before
// appctx.Boot. Even if the user's file config enables vulns or brute, zen/deep
// transforms win (D-03: mode overrides win over file config).
package config

// ApplyZenProfile applies the stealth/minimal-noise profile to cfg in memory.
//
// Zen = passive + safe probes + no active/noisy scanning. Designed for environments
// where detection avoidance is critical ("be quiet, period" — CONTEXT.md D-03).
//
// Field values sourced from RESEARCH.md Q2 "applyZenProfile" table, verified
// against defaults.go and v1 reconftw.cfg stealth semantics.
func ApplyZenProfile(cfg *Config) {
	// Lower concurrency and throughput multipliers.
	cfg.Advanced.PerfProfile = "low"
	cfg.Concurrency.MaxJobs = 2

	// Rate-limit all active probing tools to stealth levels.
	cfg.Web.Probe.RateLimit = 30  // httpx: v1 HTTPX_RATELIMIT=150 → stealth ~30
	cfg.Web.Nuclei.RateLimit = 15 // nuclei: halved from probe rate
	cfg.Web.Fuzz.RateLimit = 10   // ffuf: low rate in zen
	cfg.Web.Fuzz.Threads = 5      // ffuf: thread cap for stealth

	// Disable active/noisy subdomain sources.
	cfg.Subdomains.Brute.Enabled = false  // no DNS brute-force in zen
	cfg.Subdomains.Permut.Enabled = false // no permutation expansion in zen

	// Disable active port scanning.
	cfg.Web.Portscan.ActiveEnabled = false // no nmap/naabu in zen

	// Zen never runs vulnerability scans (zen ≈ passive+safe, recon-level only).
	cfg.Vulns.Enabled = false

	// Quiet output — "be quiet, period" (CONTEXT.md Specifics).
	cfg.Output.Verbosity = 0

	// Disable gato (active GitHub Actions audit — makes credentialed GitHub API calls).
	cfg.OSINT.GitHub.ActionsAudit.Enabled = false
}

// ApplyDeepProfile applies the extended scan profile to cfg in memory.
//
// Deep = all + recursive subdomain enum + advanced/extended fuzz & permutations.
// Sets Advanced.Deep=true so tasks can honor the deep-limit thresholds.
//
// Field values sourced from RESEARCH.md Q2 "applyDeepProfile" table, verified
// against defaults.go and v1 reconftw.cfg DEEP=true semantics.
func ApplyDeepProfile(cfg *Config) {
	// Primary gate — tasks check cfg.Advanced.Deep to decide whether to enable
	// deep-mode behaviors (e.g. VulnSpray.DeepOnly is already true by default;
	// setting Advanced.Deep=true enables it at runtime).
	cfg.Advanced.Deep = true

	// DeepLimit (500) and DeepLimit2 (1500) intentionally stay at their defaults —
	// tasks use these as thresholds to skip when count > limit && !Deep.
	// Setting Advanced.Deep=true is sufficient to disable the skip condition.

	// Enable recursive subdomain enumeration.
	cfg.Subdomains.Recursive.BruteEnabled = true
	cfg.Subdomains.Recursive.PassiveEnabled = true

	// Full permutation wordlist mode.
	cfg.Subdomains.Permut.WordlistMode = "full"

	// Deeper web fuzzing.
	cfg.Web.Fuzz.RecursionDepth = 4

	// Extended port scan — top 10000 ports vs default top 1000.
	cfg.Web.Portscan.Naabu.Ports = "--top-ports 10000"
}

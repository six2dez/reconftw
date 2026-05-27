// SPDX-License-Identifier: MIT
// Spike PoC — DO NOT EVOLVE INTO PRODUCTION
// Source: .planning/phases/01-language-adr-spike/01-02-PLAN.md Task 3
// Locked scope: spike/README.md §Scope
// Pattern reference: .planning/phases/01-language-adr-spike/01-RESEARCH.md §1.1 (OQ4)
// Bash reference: modules/subdomains.sh:sub_passive() (lines 507-553)
package passive

import (
	"context"
	"os"

	"github.com/six2dez/reconftw/spike/go/internal/proc"
	"github.com/six2dez/reconftw/spike/go/internal/ui"
)

// githubRun invokes github-subdomains via proc.Run if GITHUB_TOKENS env var is set.
// Per OQ4 (locked in spike/README.md): reads token file path from env var GITHUB_TOKENS.
// If unset or file empty/unreadable: logs [SKIP] and returns nil.
// T-01-02-SI-02: token path from env var (not CLI arg → not in ps); pass to subprocess
// as file path (-t), not token contents. Never echo env var value in logs.
func githubRun(ctx context.Context, target string, collect func(subdomain, source string)) error {
	tokensPath := os.Getenv("GITHUB_TOKENS")
	if tokensPath == "" {
		ui.Skip("github-subdomains", "GITHUB_TOKENS env var not set")
		return nil
	}

	// Validate token file is readable and non-empty.
	if info, err := os.Stat(tokensPath); err != nil || info.Size() == 0 {
		ui.Skip("github-subdomains", "GITHUB_TOKENS file not found or empty")
		return nil
	}

	ui.Info("github-subdomains: starting for " + target)

	// Command: github-subdomains -d <target> -t <tokens_file> -k -q
	// -k: skip preflight check; -q: quiet mode
	args := []string{"-d", target, "-t", tokensPath, "-k", "-q"}

	count := 0
	err := proc.Run(ctx, "github-subdomains", args, func(line []byte) error {
		subdomain := string(line)
		if subdomain != "" {
			collect(subdomain, "github")
			count++
		}
		return nil
	})

	if err != nil {
		ui.Warn("github-subdomains: exited with error: " + err.Error())
		return nil
	}

	ui.Info("github-subdomains: collected " + itoa(count) + " subdomains")
	return nil
}

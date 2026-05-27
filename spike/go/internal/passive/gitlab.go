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

// gitlabRun invokes gitlab-subdomains via proc.Run if GITLAB_TOKENS env var is set.
// Per OQ4 (locked in spike/README.md): reads token file path from env var GITLAB_TOKENS.
// If unset or file empty/unreadable: logs [SKIP] and returns nil.
// T-01-02-SI-02: same token-file-path pattern as githubRun.
func gitlabRun(ctx context.Context, target string, collect func(subdomain, source string)) error {
	tokensPath := os.Getenv("GITLAB_TOKENS")
	if tokensPath == "" {
		ui.Skip("gitlab-subdomains", "GITLAB_TOKENS env var not set")
		return nil
	}

	// Validate token file is readable and non-empty.
	if info, err := os.Stat(tokensPath); err != nil || info.Size() == 0 {
		ui.Skip("gitlab-subdomains", "GITLAB_TOKENS file not found or empty")
		return nil
	}

	ui.Info("gitlab-subdomains: starting for " + target)

	// Command: gitlab-subdomains -d <target> -t <tokens_file>
	args := []string{"-d", target, "-t", tokensPath}

	count := 0
	err := proc.Run(ctx, "gitlab-subdomains", args, func(line []byte) error {
		subdomain := string(line)
		if subdomain != "" {
			collect(subdomain, "gitlab")
			count++
		}
		return nil
	})

	if err != nil {
		ui.Warn("gitlab-subdomains: exited with error: " + err.Error())
		return nil
	}

	ui.Info("gitlab-subdomains: collected " + itoa(count) + " subdomains")
	return nil
}

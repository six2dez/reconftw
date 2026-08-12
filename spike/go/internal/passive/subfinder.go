// SPDX-License-Identifier: MIT
// Spike PoC — DO NOT EVOLVE INTO PRODUCTION
// Source: .planning/phases/01-language-adr-spike/01-02-PLAN.md Task 3
// Locked scope: spike/README.md §Scope
// Pattern reference: .planning/phases/01-language-adr-spike/01-RESEARCH.md §1.1
// Bash reference: modules/subdomains.sh:sub_passive() (lines 507-553)
package passive

import (
	"context"
	"encoding/json"

	"github.com/six2dez/reconftw/spike/go/internal/proc"
	"github.com/six2dez/reconftw/spike/go/internal/ui"
)

// subfinderOutput is the NDJSON shape from subfinder -json.
// Minimal fields — only host is needed.
type subfinderOutput struct {
	Host string `json:"host"`
}

// subfinderRun invokes subfinder via proc.Run and collects subdomains.
// Output format: NDJSON (streaming) — one JSON object per line.
// Command: subfinder -d <target> -silent -json -all -max-time 180
func subfinderRun(ctx context.Context, target string, collect func(subdomain, source string)) error {
	ui.Info("subfinder: starting for " + target)

	args := []string{"-d", target, "-silent", "-json", "-all", "-max-time", "180"}
	var count int

	err := proc.Run(ctx, "subfinder", args, func(line []byte) error {
		var out subfinderOutput
		if err := json.Unmarshal(line, &out); err != nil {
			// Skip malformed lines — subfinder can emit status lines in some modes.
			return nil
		}
		if out.Host != "" {
			collect(out.Host, "subfinder")
			count++
		}
		return nil
	})
	if err != nil {
		ui.Warn("subfinder: exited with error: " + err.Error())
		// Non-fatal: return nil so errgroup doesn't cancel other sources.
		return nil
	}

	ui.Info("subfinder: collected " + itoa(count) + " subdomains")
	return nil
}

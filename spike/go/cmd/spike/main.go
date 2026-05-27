// SPDX-License-Identifier: MIT
// Spike PoC — DO NOT EVOLVE INTO PRODUCTION
// Source: .planning/phases/01-language-adr-spike/01-02-PLAN.md Task 3
// Locked scope: spike/README.md §Scope
// Pattern reference: .planning/phases/01-language-adr-spike/01-RESEARCH.md §Pattern 1
//
// STATUS at Plan 01-02 close:
//   - Slice complete: 4 passive sources + httpx probe + atomic JSONL writes
//   - Tests: 5/5 unit, integration gated by -tags=integration
//   - Measurements captured: spike/go/out/.killtree_result, .xplat_ordinal; spike/.spike_sessions.log
//   - Awaiting Plan 01-03 (Python spike) for head-to-head comparison
package main

import (
	"fmt"
	"os"
	"os/signal"
	"regexp"
	"syscall"

	"github.com/six2dez/reconftw/spike/go/internal/httpxprobe"
	"github.com/six2dez/reconftw/spike/go/internal/passive"
	"github.com/six2dez/reconftw/spike/go/internal/ui"
	"github.com/spf13/cobra"
)

// domainRe validates target domains per T-01-02-SI-01 threat mitigation:
// rejects shell metacharacters. Mirrors validate_domain() in lib/validation.sh.
var domainRe = regexp.MustCompile(`^[a-zA-Z0-9.-]+$`)

func main() {
	var target string

	root := &cobra.Command{
		Use:   "spike",
		Short: "reconFTW v2 language spike — throwaway PoC",
		Long:  "Spike PoC: 4 passive sources + httpx probe + atomic JSONL writes. DO NOT EVOLVE INTO PRODUCTION.",
		RunE: func(cmd *cobra.Command, args []string) error {
			// T-01-02-SI-01: validate --target before passing to subprocess
			if !domainRe.MatchString(target) {
				return fmt.Errorf("invalid target %q: must match ^[a-zA-Z0-9.-]+$", target)
			}

			// Signal handler: SIGINT/SIGTERM cancel the entire pipeline context.
			// Go's signal.NotifyContext ensures ctx is cancelled on first signal;
			// proc.Run's Cancel handler propagates SIGTERM to the process group.
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			if err := os.MkdirAll("out", 0o755); err != nil {
				return fmt.Errorf("create out dir: %w", err)
			}

			// Phase 1: passive subdomain fan-out → out/subs.jsonl
			ui.Info("passive: starting for target=" + target)
			if err := passive.Run(ctx, target, "out/subs.jsonl"); err != nil {
				ui.Err("passive: " + err.Error())
				os.Exit(1)
			}

			// Phase 2: httpx probe → out/hosts.jsonl
			ui.Info("httpx: probing")
			if err := httpxprobe.Run(ctx, "out/subs.jsonl", "out/hosts.jsonl"); err != nil {
				ui.Err("httpx: " + err.Error())
				os.Exit(1)
			}

			ui.Info("spike: done")
			os.Exit(0)
			return nil
		},
	}

	root.Flags().StringVarP(&target, "target", "t", "", "Target domain (required)")
	if err := root.MarkFlagRequired("target"); err != nil {
		fmt.Fprintf(os.Stderr, "flag error: %v\n", err)
		os.Exit(1)
	}

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

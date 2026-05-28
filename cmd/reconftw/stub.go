// stub.go — D-02 phase-pointer helper.
//
// Source: .planning/phases/03-foundation-kernel/03-CONTEXT.md §"Decisions" D-02.
// All stubbed v2 subcommands (12 of 15 visible — recon/all/passive/subs/web/
// vulns/osint/zen/deep/monitor/report/mcp/migrate/install) call this helper
// to surface a phase-pointer error to stderr and exit with code 64
// (sysexits.h EX_USAGE — machine-detectable "not implemented" state).
//
// The subcommand's `--help` continues to work fully (cobra builds Use/Short/
// Long/Flags); only the RunE action returns this stub error.

package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// stubNotImplemented returns the canonical D-02 phase-pointer error.
// Format (per D-02):
//
//	`reconftw <subcommand>` is not yet implemented — ships in Phase N
//	(<Phase Name>). See .planning/ROADMAP.md for status.
//
// Exit code: 64 (EX_USAGE). Callers (cobra Execute → main.run → main.main)
// recognize the *exitCodeError type and call os.Exit(ec.code).
func stubNotImplemented(cmd *cobra.Command, phaseNum int, phaseName string) error {
	msg := fmt.Sprintf("`reconftw %s` is not yet implemented — ships in Phase %d (%s). See .planning/ROADMAP.md for status.",
		cmd.Name(), phaseNum, phaseName)
	fmt.Fprintln(cmd.ErrOrStderr(), msg)
	return &exitCodeError{code: 64, msg: ""}
}

// exitCodeError lets a deeply-nested cobra RunE communicate a specific
// process-exit code to main(). Used for D-02 stubs (code 64) and the
// kernel-demo command (code 2 when --target is missing).
type exitCodeError struct {
	code int
	msg  string
}

func (e *exitCodeError) Error() string { return e.msg }
func (e *exitCodeError) ExitCode() int { return e.code }

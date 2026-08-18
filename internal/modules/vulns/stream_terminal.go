// stream_terminal.go — the vulns package's half of the F6 terminal-error
// contract (plan 15-14 Task 2). Mirrors internal/modules/web/stream_terminal.go.
//
// Backend.Stream has TWO independent failure channels and they mean opposite
// things (see the package comment on internal/core/backend/stream.go):
//
//	ch, err := app.Tools.Stream(ctx, tool, args)
//	if err != nil { ... }              // DISPATCH: the tool is not on PATH.
//	                                   // The stream NEVER RAN.
//	                                   // => keep the existing best-effort
//	                                   //    task.StatusSkipped / log-and-continue
//	                                   //    handling. `vulns` is PolicyBestEffort
//	                                   //    (internal/core/scheduler/policy.go)
//	                                   //    and an incomplete optional toolchain
//	                                   //    must not fail a run.
//	if err := backend.Drain(ch); err != nil { ... }
//	                                   // TERMINAL: the scanner RAN and ended
//	                                   // badly (non-zero exit, scanner overflow).
//	                                   // Whatever it wrote is partial, and
//	                                   // anything already on disk is STALE.
//	                                   // => task.StatusErrored, and do NOT parse
//	                                   //    its output file.
//
// WHY THIS MATTERS MOST HERE. Several vulns scanners drain a stream and then
// immediately os.ReadFile the output path the tool was given — ssti.go's TInjA
// report directory, nuclei_dast.go's -o file, crlf.go's -o file. Before this
// migration, a scanner killed by OOM or dying on a malformed template was
// indistinguishable from one that finished clean: the channel simply closed, the
// (truncated, or entirely PREVIOUS-run) file was parsed, and the result was
// published as this run's verdict. A vulnerability scanner reporting a stale
// "clean" is the worst failure mode this tool has.
//
// Six vulns sites consume the stream inside a helper that returns
// (records, error) to a Run which treats scanner errors as best-effort and logs
// them at Debug. Returning a plain error there would be swallowed exactly as
// before, so the ratchet would go green with no behavioural change.
// errToolStreamEnded is the marker that prevents that: helpers wrap terminal
// failures with terminalStreamError, and Run escalates only those.
//
// Source: .planning/phases/15-release-gates-run-isolation-store-integrity/15-14-PLAN.md
package vulns

import (
	"errors"
	"fmt"
)

// errToolStreamEnded marks a TERMINAL stream failure — the scanner ran and
// exited badly. It never marks a dispatch failure.
var errToolStreamEnded = errors.New("tool stream ended badly")

// terminalStreamError wraps a backend.Drain / backend.Collect error so a caller
// can recognise it with errors.Is(err, errToolStreamEnded) while still seeing
// the tool name and the original cause.
func terminalStreamError(toolName string, err error) error {
	return fmt.Errorf("%s: %w: %w", toolName, errToolStreamEnded, err)
}

// isTerminalStreamError reports whether err came from a stream that STARTED and
// then ended badly, as opposed to a scanner that was never dispatched.
func isTerminalStreamError(err error) bool {
	return errors.Is(err, errToolStreamEnded)
}

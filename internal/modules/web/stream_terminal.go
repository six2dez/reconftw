// stream_terminal.go — the web package's half of the F6 terminal-error contract.
//
// Backend.Stream has TWO independent failure channels and they mean opposite
// things (see the package comment on internal/core/backend/stream.go):
//
//	ch, err := app.Tools.Stream(ctx, tool, args)
//	if err != nil { ... }              // DISPATCH: the tool is not on PATH.
//	                                   // The stream NEVER RAN.
//	                                   // => task.StatusSkipped. Never escalate:
//	                                   //    internal/core/scheduler/policy.go
//	                                   //    gives `subdomains` PolicyFailFast, so
//	                                   //    escalating a missing optional tool
//	                                   //    fails whole runs on hosts that simply
//	                                   //    did not install it.
//	if err := backend.Drain(ch); err != nil { ... }
//	                                   // TERMINAL: the tool RAN and ended badly
//	                                   // (non-zero exit, scanner overflow).
//	                                   // Whatever it wrote is partial, and
//	                                   // anything already on disk is STALE.
//	                                   // => task.StatusErrored, and do NOT parse
//	                                   //    the staging file.
//
// Several web tasks split the stream consumption into a per-host or per-group
// helper that returns (records, error) to a Run that treats tool errors as
// best-effort and logs them. Without a marker, a terminal error from such a
// helper is indistinguishable from "this host produced nothing" and would be
// swallowed exactly as before. errToolStreamEnded is that marker: helpers wrap
// it, Run tests for it with errors.Is and escalates to StatusErrored.
//
// Source: .planning/phases/15-release-gates-run-isolation-store-integrity/15-13-PLAN.md
package web

import (
	"errors"
	"fmt"
)

// errToolStreamEnded marks a TERMINAL stream failure — the tool ran and exited
// badly. It never marks a dispatch failure.
var errToolStreamEnded = errors.New("tool stream ended badly")

// terminalStreamError wraps a backend.Drain / backend.Collect error so a caller
// can recognise it with errors.Is(err, errToolStreamEnded) while still seeing
// the tool name and the original cause.
func terminalStreamError(toolName string, err error) error {
	return fmt.Errorf("%s: %w: %w", toolName, errToolStreamEnded, err)
}

// isTerminalStreamError reports whether err came from a stream that STARTED and
// then ended badly, as opposed to a tool that was never dispatched.
func isTerminalStreamError(err error) bool {
	return errors.Is(err, errToolStreamEnded)
}

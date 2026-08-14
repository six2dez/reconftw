// SPDX-License-Identifier: MIT
//
// Negative fixtures for the stream-contract detector (see
// internal/modules/stream_contract_test.go).
//
// Each function here consumes a stream in a way that DROPS the terminal
// Event.Err, and the detector must report all three as violations. Two of them
// are near-misses chosen deliberately:
//
//   - accumulatorAssignedNeverChecked is identical to accumulatorOK except for
//     the missing post-loop nil check, so a detector that merely greps for
//     "ev.Err" would wave it through.
//   - streamErrOnlyBad handles the Stream() DISPATCH error. That is the
//     missing-tool path (task.StatusSkipped) and says nothing whatsoever about
//     the terminal error, so a detector that treats any error handling near a
//     Stream call as sufficient would wave it through too.
//
// See good_shapes.go for why these fixtures live under testdata/.
package streamcontract

import (
	"os"

	"github.com/six2dez/reconftw/internal/core/task"
)

// accumulatorAssignedNeverChecked — REJECTED. ev.Err is assigned and then
// dropped on the floor; the function returns StatusDone regardless.
func accumulatorAssignedNeverChecked(ctx context, app *appCtx) (task.Result, error) {
	eventCh, err := app.Tools.Stream(ctx, "ffuf", nil)
	if err != nil {
		return task.Result{Status: task.StatusSkipped}, nil
	}

	var streamErr error
	var lines int
	for ev := range eventCh {
		if ev.Err != nil {
			streamErr = ev.Err
			continue
		}
		lines++
	}
	_ = streamErr

	return task.Result{Status: task.StatusDone, Stats: map[string]int{"lines": lines}}, nil
}

// bareRangeBad — REJECTED. This is the pre-migration shape of the 9 bare-drain
// sites and the exact Gate-5 failure mode: the tool exits 7, the drain ignores
// it, and os.ReadFile parses a truncated or entirely stale staging file.
func bareRangeBad(ctx context, app *appCtx) (task.Result, error) {
	eventCh, err := app.Tools.Stream(ctx, "nuclei", nil)
	if err != nil {
		return task.Result{Status: task.StatusSkipped}, nil
	}
	// Drain stream (Backend contract: caller MUST drain until closed).
	for range eventCh { //nolint:revive // intentional drain
	}

	data, readErr := os.ReadFile("inputs/findings.nuclei.jsonl")
	if readErr != nil {
		return task.Result{Status: task.StatusErrored}, readErr
	}
	return task.Result{Status: task.StatusDone, Stats: map[string]int{"bytes": len(data)}}, nil
}

// streamErrOnlyBad — REJECTED. It handles the DISPATCH error correctly (the
// missing-tool -> StatusSkipped path that F6 must not disturb) and then ignores
// the terminal error completely.
func streamErrOnlyBad(ctx context, app *appCtx) (task.Result, error) {
	eventCh, err := app.Tools.Stream(ctx, "arjun", nil)
	if err != nil {
		// arjun not on PATH: StatusSkipped (best_effort D-W12).
		return task.Result{Status: task.StatusSkipped}, nil
	}
	var lines int
	for ev := range eventCh {
		if len(ev.Line) > 0 {
			lines++
		}
	}
	return task.Result{Status: task.StatusDone, Stats: map[string]int{"lines": lines}}, nil
}

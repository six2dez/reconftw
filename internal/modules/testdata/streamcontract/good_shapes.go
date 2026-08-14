// SPDX-License-Identifier: MIT
//
// Positive fixtures for the stream-contract detector (see
// internal/modules/stream_contract_test.go).
//
// These files live under testdata/ so the go tool never builds, vets or lints
// them — they exist ONLY to be parsed by go/parser. They are deliberately not
// compilable in isolation (the imports do not resolve to anything the detector
// needs), because the detector is a syntactic analysis and must be proven against
// syntax.
//
// Every function here is one of the four shapes plans 15-13 and 15-14 are
// permitted to produce. If the detector ever reports one of them as a violation,
// a correct migration has been turned into a red test — and the cheapest way out
// under pressure would be to re-add an allowlist entry, reopening the ratchet.
// That is why these are permanent tests rather than a one-off manual check.
package streamcontract

import (
	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/task"
)

// drainOK — accepted shape 1: backend.Drain in the function body.
//
// This is the migration target for the 9 bare-drain sites, whose old form was
//
//	for range eventCh { //nolint:revive // intentional drain
//	}
func drainOK(ctx context, app *appCtx) (task.Result, error) {
	eventCh, err := app.Tools.Stream(ctx, "nuclei", nil)
	if err != nil {
		return task.Result{Status: task.StatusSkipped}, nil
	}
	if drainErr := backend.Drain(eventCh); drainErr != nil {
		return task.Result{Status: task.StatusErrored}, drainErr
	}
	return task.Result{Status: task.StatusDone}, nil
}

// collectOK — accepted shape 2: backend.Collect in the function body.
//
// This is the migration target for the 14 ev-binding sites.
func collectOK(ctx context, app *appCtx) (task.Result, error) {
	eventCh, err := app.Tools.Stream(ctx, "sqlmap", nil)
	if err != nil {
		return task.Result{Status: task.StatusSkipped}, nil
	}
	var hits int
	collectErr := backend.Collect(eventCh, func(ev backend.Event) {
		if len(ev.Line) > 0 {
			hits++
		}
	})
	if collectErr != nil {
		return task.Result{Status: task.StatusErrored}, collectErr
	}
	return task.Result{Status: task.StatusDone, Stats: map[string]int{"hits": hits}}, nil
}

// helperOK — accepted shape 3: delegates to a same-package helper whose own body
// drains, and USES the helper's error return.
func helperOK(ctx context, app *appCtx) (task.Result, error) {
	eventCh, err := app.Tools.Stream(ctx, "katana", nil)
	if err != nil {
		return task.Result{Status: task.StatusSkipped}, nil
	}
	if consumeErr := consumeStream(eventCh); consumeErr != nil {
		return task.Result{Status: task.StatusErrored}, consumeErr
	}
	return task.Result{Status: task.StatusDone}, nil
}

// consumeStream is helperOK's same-package helper. It has no Stream call of its
// own, so it is never a violation candidate — it exists to be recognised as a
// consuming helper.
func consumeStream(ch chan backend.Event) error {
	return backend.Drain(ch)
}

// accumulatorOK — accepted shape 4: the site keeps its range loop, accumulates
// ev.Err into a variable, and CHECKS that variable after the loop.
//
// Plans 15-13 and 15-14 explicitly permit this, which is the whole reason the
// detector is AST-based: a token grep cannot distinguish this from
// accumulatorAssignedNeverChecked in bad_shapes.go, which is byte-for-byte
// identical up to the missing post-loop check.
func accumulatorOK(ctx context, app *appCtx) (task.Result, error) {
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
	if streamErr != nil {
		return task.Result{Status: task.StatusErrored}, streamErr
	}
	return task.Result{Status: task.StatusDone, Stats: map[string]int{"lines": lines}}, nil
}

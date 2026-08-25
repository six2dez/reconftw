// SPDX-License-Identifier: MIT
//
// Negative fixtures for the silent-success detector (see
// internal/modules/silent_success_test.go).
//
// Each function here is a tool-error branch the detector MUST report, and each
// is named for the rule it breaks, so a failure message citing the wrong rule
// is itself a test failure. Several are near-misses on purpose:
//
//   - producedDoneBad returns task.Produced(...) rather than a literal, so a
//     detector that only pattern-matches `Status: task.StatusDone` waves it
//     through.
//   - helperDoneBad hides the StatusDone one level down, in exactly the shape
//     the accepted helper form uses.
//   - secondCallBad has TWO tool calls, the first fully compliant. A
//     function-granular detector — the documented hole in the older
//     stream-contract ratchet — waves it through.
//   - elseBranchBad writes the nil test the other way round, so the error
//     branch is the ELSE.
//
// See good_shapes.go for why these fixtures live under testdata/.
package silentsuccess

import (
	"github.com/six2dez/reconftw/internal/core/task"
)

// statusDoneBad breaks the STATUS rule only: the failure is announced at WARN,
// but the task still reports Done. This is `[OK] subdomains.takeover.dnstake 0s`.
func statusDoneBad(ctx context, app *appCtx) (task.Result, error) {
	res, err := app.Tools.Run(ctx, "dnstake", nil)
	if err != nil {
		app.Log.Warn("dnstake run failed or tool not registered", "err", err)
		return task.Result{Status: task.StatusDone, Stats: map[string]int{"takeovers_found": 0}}, nil
	}
	_ = res
	return task.Produced("takeovers_found", 1), nil
}

// producedDoneBad breaks the STATUS rule through the constructor rather than a
// literal.
func producedDoneBad(ctx context, app *appCtx) (task.Result, error) {
	res, err := app.Tools.RunEnv(ctx, "cewler", nil, nil)
	if err != nil {
		app.Log.Error("cewler: tool failed", "err", err)
		return task.Produced("words_found", 0), nil
	}
	_ = res
	return task.Produced("words_found", 1), nil
}

// helperDoneBad breaks the STATUS rule one level down, through the same
// indirection shape helperDegradeOK is allowed to use.
func helperDoneBad(ctx context, app *appCtx) (task.Result, error) {
	res, err := app.Tools.Run(ctx, "gitdorks_go", nil)
	if err != nil {
		app.Log.Warn("gitdorks: tool failed", "err", err)
		return emptyDoneFixture()
	}
	_ = res
	return task.Produced("dorks_found", 1), nil
}

// emptyDoneFixture is the helper that makes helperDoneBad a violation. It is
// modelled on subdomains/csprecon.go's cspreconEmptyDone.
func emptyDoneFixture() (task.Result, error) {
	return task.Result{Status: task.StatusDone}, nil
}

// debugOnlyBad breaks the LOG rule only: the status is correct, but the only
// thing said about the tool failure is a Debug line nobody sees at the default
// level. This is the dnstake half that made the failure last months.
func debugOnlyBad(ctx context, app *appCtx) (task.Result, error) {
	eventCh, err := app.Tools.Stream(ctx, "commix", nil)
	if err != nil {
		app.Log.Debug("vulns.cmdi: commix stream error (best_effort)", "err", err)
		return task.Result{Status: task.StatusSkipped, Reason: "commix failed"}, nil
	}
	_ = eventCh
	return task.Produced("confirmed", 1), nil
}

// bothRulesBad is the full 2026-08-20 shape: Debug plus Done. It must produce
// TWO findings, one per rule — a reader given only one of them fixes half the
// defect.
func bothRulesBad(ctx context, app *appCtx) (task.Result, error) {
	res, err := app.Tools.StreamEnv(ctx, "subzy", nil, nil)
	if err != nil {
		app.Log.Debug("subzy run failed or tool not registered", "err", err)
		return task.Result{Status: task.StatusDone, Stats: map[string]int{"takeovers_found": 0}}, nil
	}
	_ = res
	return task.Produced("takeovers_found", 1), nil
}

// secondCallBad is the granularity proof. The naabu branch is compliant; the
// nmap branch below it is not. A detector that decides once per FUNCTION sees
// the compliant branch and passes.
func secondCallBad(ctx context, app *appCtx) (task.Result, error) {
	res, err := app.Tools.Run(ctx, "naabu", nil)
	if err != nil {
		app.Log.Warn("web.portscan: naabu absent/failed", "err", err)
		return task.Result{Status: task.StatusSkipped}, nil
	}
	_ = res
	nres, nerr := app.Tools.Run(ctx, "nmap", nil)
	if nerr != nil {
		app.Log.Debug("web.portscan: nmap targeted scan failed", "err", nerr)
		return task.Result{Status: task.StatusDone}, nil
	}
	_ = nres
	return task.Produced("ports_found", 1), nil
}

// elseBranchBad writes the nil test the other way round, so the error branch is
// the ELSE. A detector that only looks at IfStmt.Body misses it.
func elseBranchBad(ctx context, app *appCtx) (task.Result, error) {
	res, err := app.Tools.Run(ctx, "smap", nil)
	if err == nil {
		_ = res
	} else {
		app.Log.Debug("web.portscan: smap failed", "err", err)
		return task.Result{Status: task.StatusDone}, nil
	}
	return task.Produced("ports_found", 1), nil
}

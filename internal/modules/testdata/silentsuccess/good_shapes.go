// SPDX-License-Identifier: MIT
//
// Positive fixtures for the silent-success detector (see
// internal/modules/silent_success_test.go).
//
// These files live under testdata/ so the go tool never builds, vets or lints
// them — they exist ONLY to be parsed by go/parser, and are deliberately not
// compilable in isolation. The detector is a syntactic analysis and must be
// proven against syntax.
//
// Every function here is a shape a correct fix is allowed to produce. If the
// detector ever reports one of them, a correct fix has been turned into a red
// test, and the cheapest way out under pressure would be to add an allowlist
// entry — reopening the ratchet. That is why these are permanent tests and not
// a one-off manual check.
package silentsuccess

import (
	"github.com/six2dez/reconftw/internal/core/task"
)

// literalSkipOK — accepted shape 1: a Result literal with a non-Done status,
// announced at WARN.
func literalSkipOK(ctx context, app *appCtx) (task.Result, error) {
	res, err := app.Tools.Run(ctx, "subzy", nil)
	if err != nil {
		app.Log.Warn("subzy: tool failed — takeover detection did not run", "err", err)
		return task.Result{Status: task.StatusSkipped, Reason: "subzy failed"}, nil
	}
	_ = res
	return task.Produced("takeovers_found", 1), nil
}

// erroredLiteralOK — a Result literal with StatusErrored and a propagating
// error. web/httpx.go's tool-error branch is exactly this, and logs nothing
// because the scheduler surfaces the returned error.
func erroredLiteralOK(ctx context, app *appCtx) (task.Result, error) {
	res, err := app.Tools.Run(ctx, "httpx", nil)
	if err != nil {
		return task.Result{Status: task.StatusErrored}, wrap(err)
	}
	_ = res
	return task.Produced("hosts_found", 1), nil
}

// helperDegradeOK — accepted shape 2: ONE level of same-package indirection.
// This is subdomains/resolve.go's runExecTask → degradeResolveTool shape, the
// one that carries the CONTINUE_ON_TOOL_ERROR contract.
func helperDegradeOK(ctx context, app *appCtx) (task.Result, error) {
	res, err := app.Tools.Run(ctx, "puredns", nil)
	if err != nil {
		return degradeFixture(app, "puredns", err)
	}
	_ = res
	return task.Produced("subdomains_found", 1), nil
}

// degradeFixture is the helper resolved by shape 2. Its own returns are all
// accepted statuses, so a branch that returns it is accepted.
func degradeFixture(app *appCtx, tool string, cause error) (task.Result, error) {
	if propagating(cause) {
		return task.Result{Status: task.StatusErrored}, cause
	}
	app.Log.Warn("resolve: tool failed (non-fatal degrade)", "tool", tool, "error", cause)
	return task.ToolDegraded(tool, cause), nil
}

// nothingProducedOK — task.NothingProduced is rule B2's constructor and is a
// StatusSkipped by construction.
func nothingProducedOK(ctx context, app *appCtx) (task.Result, error) {
	res, err := app.Tools.RunEnv(ctx, "dnsx", nil, nil)
	if err != nil {
		app.Log.Error("dnsx: tool failed", "err", err)
		return task.NothingProduced("dnsx: " + err.Error()), nil
	}
	_ = res
	return task.Produced("resolved", 1), nil
}

// fallThroughOK — accepted shape 3: the branch returns nothing and the function
// carries on with an empty result. subdomains/resolve.go dnsxRecon does this.
func fallThroughOK(ctx context, app *appCtx) (task.Result, error) {
	var raw []byte
	res, err := app.Tools.Run(ctx, "dnsx", nil)
	if err != nil {
		app.Log.Warn("resolve: dnsx recon failed (non-fatal degrade)", "error", err)
	} else {
		raw = res.Stdout
	}
	return task.Produced("records", len(raw)), nil
}

// debugBesideWarnOK — a Debug line is fine when the SAME branch also says
// something at Info or above. The failure is announced; the Debug line is
// detail. Reporting this would flag correct code, which is how a detector gets
// disabled by the first person it inconveniences.
func debugBesideWarnOK(ctx context, app *appCtx) (task.Result, error) {
	res, err := app.Tools.Run(ctx, "gf", nil)
	if err != nil {
		app.Log.Warn("vulns.gf: gf invocation failed", "err", err)
		app.Log.Debug("vulns.gf: argv was", "args", res)
		return task.Result{Status: task.StatusSkipped, Reason: "gf failed"}, nil
	}
	return task.Produced("matched", 1), nil
}

// infoOnlyOK — Info is the DEFAULT handler level (internal/core/config/
// defaults.go logLevel), so an Info line about the tool failure is on the
// operator's screen. Accepted; counted separately in the census.
func infoOnlyOK(ctx context, app *appCtx) (task.Result, error) {
	eventCh, err := app.Tools.Stream(ctx, "katana", nil)
	if err != nil {
		app.Log.Info("web.katana: binary absent or failed — skipping", "err", err)
		return task.Result{Status: task.StatusSkipped}, nil
	}
	_ = eventCh
	return task.Produced("urls_found", 1), nil
}

// noErrorBranchOK — a tool call whose error is never tested against nil. There
// is no branch to inspect, so nothing is reported. This is a BLIND SPOT, not a
// pass; the package comment says so and the fixture pins the behaviour rather
// than blessing it.
func noErrorBranchOK(ctx context, app *appCtx) (task.Result, error) {
	res, _ := app.Tools.Run(ctx, "whois", nil)
	return task.Produced("bytes", len(res.Stdout)), nil
}

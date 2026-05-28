// Package lint provides the FOUND-10 scaffold for forbidding raw `exec.Command` /
// `exec.CommandContext` / `(*exec.Cmd).Run` / `(*exec.Cmd).Start` calls outside
// internal/core/backend/local.go.
//
// Phase 3 Plan 04 ships this as a test-based AST scan that runs on every CI push.
// The scan uses `go/ast` + `golang.org/x/tools/go/packages` to walk every package
// under ./internal/... (per Blocker 8). Implementation lives in
// no_raw_subprocess_test.go.
//
// FOUND-10: "Lint rule (golangci-lint custom check or ruff plugin) forbids raw
// subprocess invocation outside the Tool wrapper; CI gate"
// (REQUIREMENTS.md line 49; ROADMAP success criterion 3).
//
// Allowlist (paths where direct os/exec calls ARE permitted):
//
//   - internal/core/backend/local.go            — THE Backend.Exec / Stream call site
//   - internal/core/backend/local_test.go       — exercises LocalBackend
//   - internal/core/backend/local_smoke_test.go — FOUND-09 kill-tree smoke test
//   - internal/core/backend/registry.go         — exec.LookPath (Discover path resolution)
//   - internal/core/backend/registry_test.go    — exercises Discover
//   - internal/core/testutil/                   — mock backends + test fixtures (prefix)
//   - internal/core/backend/lint/testdata/      — fixture file used to validate scanner
//
// Replacement contract: callers OUTSIDE the allowlist must call
// `app.Tools.Run(ctx, name, args)` or `app.Tools.Stream(ctx, name, args)`
// (the canonical Backend Runner shape — ADR §5.3 line 1727).
//
// Upgrade path to a real golangci-lint v2 custom plugin:
//
//  1. Create cmd/foundlint-no-raw-subprocess/main.go implementing the v2 module-plugin API.
//  2. Reference in .golangci.yml under `linters.settings.custom`.
//  3. Replace this scaffold with a passthrough doc note. The Phase 4+ ticket that
//     does this swap is OUT-OF-SCOPE for Plan 04; the test-based approach is the
//     Plan-04-shipped enforcement.
package lint

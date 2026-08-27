// Package lint is the FOUND-10 gate: raw `exec.Command` / `exec.CommandContext`
// / `(*exec.Cmd).Run` / `(*exec.Cmd).Start` are forbidden outside the Runner
// seam. The scan is an AST walk over every package under ./internal/... using
// `go/ast` + `golang.org/x/tools/go/packages`, and it runs on every CI push.
//
// FOUND-10: "Lint rule (golangci-lint custom check or ruff plugin) forbids raw
// subprocess invocation outside the Tool wrapper; CI gate"
// (REQUIREMENTS.md line 49; ROADMAP success criterion 3).
//
// # Why the allowlist was replaced (plan 18-03, RS-C)
//
// Until 18-03 the exemption mechanism was a []string of repo-relative paths with
// free-text comments. It failed — six undocumented bypasses shipped through it —
// and the mechanism was established by EXPERIMENT rather than by reading the rule
// (all four steps and their output are recorded in 18-03-SUMMARY.md):
//
//   - A new file under internal/modules/ with one direct dispatch and no
//     allowlist entry FAILED the gate. So the rule always fired.
//   - Appending that file's path with a comment claiming a reason KNOWN TO BE
//     FALSE for it turned the gate GREEN.
//
// The failure mode was therefore never "the rule does not fire". It is that the
// remedy the rule invites — one line of path plus one paragraph of prose — IS the
// bypass, and nothing ever checked that the prose was true, or still true.
//
// # The two sources that replaced it
//
// Both live in bypasses.go (data) and bypasses_test.go (predicates and gate):
//
//   - infrastructureAllowlist — the files that ARE the seam and its own tests
//     (local.go, registry.go, testutil/, lint/testdata/ and the seam's test
//     files). These are kept EXPLICITLY SEPARATE from the manifest rather than
//     folded into it: the manifest is a shrinking census of work still owed, and
//     local.go's four permanent dispatch sites would give that census an
//     irreducible floor that can never express "done". They also carry no reason,
//     because they are not exceptions.
//
//   - lint.Bypasses — the typed bypass manifest. Every entry declares a reason
//     SET drawn from a CLOSED vocabulary, an EXACT dispatch-site count, the tool
//     it dispatches, prose for a human, and optionally the plan that will route it
//     home.
//
// # The corroboration contract
//
// A manifest entry is not self-certifying. Four checks run against it, and each
// one is proven to FIRE against a deliberately-broken testdata fixture rather
// than merely to pass on a good input:
//
//  1. UNLISTED — a file with >=1 dispatch site and no manifest entry fails. This
//     is the one thing the string allowlist did right, preserved exactly.
//  2. STALE — an entry naming a file with ZERO dispatch sites fails. A
//     justification that outlives the code it justified is unfalsifiable prose.
//  3. SITE DRIFT — `Sites` must EQUAL the walker's count, not merely bound it,
//     and the check is proven to fail in both directions. A `>=` check would wave
//     through a second, undocumented dispatch added to an already-forgiven file.
//  4. REASONS — every declared reason must have a corroboration predicate (the
//     vocabulary is CLOSED: an unknown reason fails rather than defaulting to
//     permitted), that predicate must find evidence in THE DECLARED FILE'S OWN
//     SYNTAX TREE, and the declared reason set must together explain EVERY
//     dispatch site in the file — a two-shape file cannot hide its second shape
//     behind its first shape's reason.
//
// The vocabulary and what corroborates each member:
//
//	stdin                — an assignment to the Stdin field of an *os/exec.Cmd
//	work_dir             — the same, for the Dir field
//	clone_path           — the dispatched executable, or its leading script
//	                       argument, is built with filepath.Join rather than
//	                       being a bare tool name
//	process_lifecycle    — a SysProcAttr assignment, or a signal to a negative pid
//	non_recon_binary     — the dispatched name is not a tools.lock entry (checked
//	                       against the manifest, never a hand-written list)
//	installer_toolchain  — the file is under internal/installer/
//	pending_removal      — requires a non-empty HomeBy naming the owning plan
//
// Receiver types are resolved through `pkg.TypesInfo`, never by matching an
// identifier spelled "cmd": an identifier match would pass on any variable a
// developer happened to name `cmd` and would MISS the real receiver at
// vulns/xss.go:291, which is named `gxssCmd`.
//
// # The census
//
// The gate emits `BYPASS_CENSUS files=<n> sites=<n>` and pins both numbers as
// constants. The rule is the one the arg-vector census states: a change to
// either constant must be a VISIBLE DIFF WITH A WRITTEN REASON. Plans 18-04 and
// 18-05 lower them in the same change that routes a file home; nothing may raise
// them without a new, corroborated entry.
//
// # Replacement contract
//
// Callers outside the two sources above must dispatch through the Runner seam:
//
//	app.Tools.Run(ctx, name, args)                                // buffered
//	app.Tools.Stream(ctx, name, args)                             // streaming
//	app.Tools.RunOpts(ctx, name, args, backend.ExecOptions{...})
//	app.Tools.StreamOpts(ctx, name, args, backend.ExecOptions{...})
//
// WR-11: the streaming lines used to show an `onLine` callback parameter that has
// never existed. This block is the replacement contract the gate points a
// developer at when it fires, so it is the ONE comment in this file that must
// compile in a reader's head. Stream and StreamOpts return `<-chan Event`; drain
// it to completion or the child leaks. See backend.Collect / backend.Drain for
// the consumption helpers.
// RunOpts/StreamOpts shipped in 18-01 and carry `Env`, `Stdin` ([]byte),
// `StdinPath` (mutually exclusive with Stdin) and `Dir`. 18-02 added declared
// repo-clone coordinates to tools.lock (clone_dir / clone_entry /
// clone_interpreter / clone_workdir), which populate `Tool.ArgvPrefix` and
// `Tool.WorkDir`. Between them, `stdin`, `work_dir` and `clone_path` are
// capabilities the seam NOW HAS — which is why several entries in the manifest
// record their own reason as obsolete and are owed a `HomeBy`.
//
// # Upgrade path to a real golangci-lint v2 custom plugin
//
//  1. Create cmd/foundlint-no-raw-subprocess/main.go implementing the v2
//     module-plugin API.
//  2. Reference it in .golangci.yml under `linters.settings.custom`.
//  3. Replace this test-based scaffold with a passthrough doc note. The manifest
//     and its predicates port across unchanged; only the driver changes.
package lint

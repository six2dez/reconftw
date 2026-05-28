// Source: .planning/phases/03-foundation-kernel/03-03-PLAN.md Task 5 (W15).
//
// Interface abstracts the checkpoint store so Plan 04 Scheduler and
// Plan 05 AppContext can type their checkpoint field on the interface,
// allowing Plan 07 MockCheckpoint substitution without SQLite. The
// concrete *Store is the production implementation; *testutil.MockCheckpoint
// (Plan 07) is the in-memory test double.
//
// Introducing the interface here — at the same time as the concrete type
// — costs nothing and prevents the Plan 04-07 refactor cycle that would
// otherwise be needed to widen *Store into an interface after the fact.
package checkpoint

import "context"

// Interface is the kernel-facing contract for task checkpoint persistence.
// Adding a method here is a non-breaking addition per ADR §0 D-07; any
// implementation (production *Store or test mocks) MUST also implement
// the new method or compilation fails — the var _ = (*X)(nil) lines
// below + in test packages are the enforcement gates.
type Interface interface {
	// Begin records that the task is about to execute. Idempotent —
	// re-Begin on the same triple resets to in-progress (the re-run
	// path after a Complete with an errored status).
	Begin(ctx context.Context, taskName, target, inputHash string) error

	// Complete records the terminal state — done if runErr is nil,
	// errored otherwise. outputPaths is the comma-joined record of
	// artefacts the task wrote.
	Complete(ctx context.Context, taskName, target, inputHash string,
		outputPaths []string, runErr error) error

	// Done reports whether a row with status=done exists for the triple.
	// false for "no row" and "row with non-done status" alike — both
	// cases mean "must run."
	Done(ctx context.Context, taskName, target, inputHash string) (bool, error)
}

// Compile-time assertion: concrete *Store satisfies Interface.
// Adding a method to Interface forces a compile error here unless the
// concrete type implements it — the canonical W15 enforcement gate.
var _ Interface = (*Store)(nil)

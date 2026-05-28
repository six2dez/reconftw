// Source: .planning/phases/03-foundation-kernel/03-03-PLAN.md Task 5 (W15).
//
// Interface abstracts the OutputTree's Append behaviour so Plan 04
// Scheduler + Plan 05 AppContext can type their tree field on the
// interface, allowing Plan 07 MockOutputTree substitution without disk
// I/O. The concrete *OutputTree is the production implementation;
// *testutil.MockOutputTree (Plan 07) is the in-memory test double.
package output

// Interface is the kernel-facing contract for artefact writes.
// Adding a method here is non-breaking per ADR §0 D-07; any
// implementation (production *OutputTree or test mocks) MUST also
// implement the new method or compilation fails.
type Interface interface {
	// Append writes lines to artefacts/<artefact>.jsonl, validating each
	// line against the configured ScopeFilter. Out-of-scope lines cause
	// the WHOLE batch to be rejected with *errors.OutOfScope.
	Append(artefact string, lines [][]byte) error
}

// Compile-time assertion: concrete *OutputTree satisfies Interface.
var _ Interface = (*OutputTree)(nil)

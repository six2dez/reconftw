// Source: .planning/phases/03-foundation-kernel/03-03-PLAN.md Task 5 (W15).
// Compile-time assertion: concrete *Store satisfies checkpoint.Interface.
// Plan 04 Scheduler.Checkpoint will be typed `checkpoint.Interface`;
// Plan 07 MockCheckpoint will satisfy this interface via its own
// var _ checkpoint.Interface = (*testutil.MockCheckpoint)(nil) line.
package checkpoint_test

import (
	"testing"

	"github.com/six2dez/reconftw/internal/core/checkpoint"
)

// TestCheckpointInterfaceShape exists primarily as a compile-time gate.
// The actual interface satisfaction is asserted via the package-level
// `var _ Interface = (*Store)(nil)` line in interface.go; this test
// re-states the assertion at test-binary scope so future contributors
// adding methods to Interface are forced to update Store + every Mock.
func TestCheckpointInterfaceShape(t *testing.T) {
	var _ checkpoint.Interface = (*checkpoint.Store)(nil)
	_ = t // satisfy linter; the value is the compile gate.
}

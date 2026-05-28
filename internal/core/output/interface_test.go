// Source: .planning/phases/03-foundation-kernel/03-03-PLAN.md Task 5 (W15).
// Compile-time assertion: concrete *OutputTree satisfies output.Interface.
// Plan 05 AppContext.Tree may type its field as output.Interface for tests;
// Plan 07 MockOutputTree will satisfy this interface via its own assertion.
package output_test

import (
	"testing"

	"github.com/six2dez/reconftw/internal/core/output"
)

func TestOutputInterfaceShape(t *testing.T) {
	var _ output.Interface = (*output.OutputTree)(nil)
	_ = t
}

// SPDX-License-Identifier: MIT
//
// Drift guard between the two places the gf class list is written down.
//
// The installer provisions ~/.gf and health-check verifies it, but the
// installer sits BELOW the modules layer and cannot import this package, so it
// carries its own copy of the class list. A class added to gfClasses without
// being added to installer.GFRequiredPatterns would be invoked by GFTask and
// never provisioned or checked for — reintroducing exactly the silent-zero this
// pairing exists to prevent, for that one class.

package vulns

import (
	"testing"

	"github.com/six2dez/reconftw/internal/installer"
)

func TestGFRequiredPatternsMatchesGFClasses(t *testing.T) {
	want := make(map[string]bool, len(gfClasses))
	for _, c := range gfClasses {
		want[c] = true
	}
	// Every class GFTask invokes must be accounted for on exactly one side:
	// gated by health-check, or declared unobtainable with a reason.
	accounted := make(map[string]bool)
	for _, c := range installer.GFRequiredPatterns {
		accounted[c] = true
	}
	for c := range installer.GFUnobtainablePatterns {
		if accounted[c] {
			t.Errorf("%q is BOTH required and unobtainable — health-check would gate "+
				"on a pattern declared impossible to obtain", c)
		}
		accounted[c] = true
	}

	for c := range want {
		if !accounted[c] {
			t.Errorf("gfClasses has %q but the installer neither gates on it "+
				"(GFRequiredPatterns) nor declares it unobtainable "+
				"(GFUnobtainablePatterns): GFTask would invoke a pattern that is "+
				"never provisioned and whose absence nothing reports", c)
		}
	}
	for c := range accounted {
		if !want[c] {
			t.Errorf("the installer accounts for %q but gfClasses does not invoke it: "+
				"health-check would fail an install over a pattern nothing uses", c)
		}
	}
}

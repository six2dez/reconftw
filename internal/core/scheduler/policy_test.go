// Source: .planning/phases/03-foundation-kernel/03-05-PLAN.md Task 1
// behavior test 16 — policyFor lookup.
package scheduler

import "testing"

// Test 16: policyFor("subdomains") = fail_fast; "osint" = best_effort;
// "custom" falls through to best_effort (the conservative default).
// GAP-2: "subdomains.passive" → best_effort (passive stage is non-fatal).
//
// Lives in the scheduler package (not _test) so it can call the unexported
// policyFor.
func TestPolicyFor(t *testing.T) {
	cases := []struct {
		module string
		want   FailurePolicy
	}{
		{"subdomains", PolicyFailFast},
		{"scheduler", PolicyFailFast},
		{"subdomains.passive", PolicyBestEffort}, // GAP-2: passive stage is non-fatal
		{"osint", PolicyBestEffort},
		{"web", PolicyBestEffort},
		{"vulns", PolicyBestEffort},
		{"custom", PolicyBestEffort}, // unknown → safe default
	}
	for _, c := range cases {
		got := policyFor(c.module, nil)
		if got != c.want {
			t.Errorf("policyFor(%q) = %q, want %q", c.module, got, c.want)
		}
	}

	// Override takes precedence over default.
	got := policyFor("subdomains", map[string]FailurePolicy{"subdomains": PolicyBestEffort})
	if got != PolicyBestEffort {
		t.Errorf("override: policyFor(subdomains) = %q, want best_effort", got)
	}
}

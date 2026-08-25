// require_resolvers_test.go — per-mode RequireResolvers derivation.
//
// BootReconApp turns an unobtainable resolver list into a hard startup error for
// runs that resolve DNS and a WARN for everything else. That split is only as
// good as the predicate below, and the predicate is the kind of thing that rots
// silently: a mode that gains a resolve stage later must inherit the guard
// without anyone remembering to update an allowlist. This test is what makes
// that true — it drives the REAL pipeline definition, not a copy of it.

package handlers

import "testing"

func TestStagesRequireResolversPerMode(t *testing.T) {
	cases := []struct {
		mode CompositeMode
		name string
		want bool
	}{
		{ModeRecon, "recon", true},
		{ModeAll, "all", true},
		{ModeDeep, "deep", true},
		{ModeZen, "zen", true},
		// Passive never resolves DNS, so it must stay runnable with no resolver
		// list — an offline/air-gapped passive run is a legitimate use.
		{ModePassive, "passive", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := stagesRequireResolvers(compositePipelineStages(tc.mode))
			if got != tc.want {
				t.Errorf("stagesRequireResolvers(%s) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

// TestResolveStageNameMatchesPipeline pins the constant to the real stage name.
// If the group were renamed and the constant were not, stagesRequireResolvers
// would silently return false for every mode and the startup guard would vanish
// without a single test failing — precisely the false-green shape phase 15 spent
// itself hunting.
func TestResolveStageNameMatchesPipeline(t *testing.T) {
	found := false
	for _, g := range compositePipelineStages(ModeRecon) {
		if g.name == resolveStageName {
			found = true
		}
	}
	if !found {
		t.Fatalf("no stage group named %q in the recon pipeline — the RequireResolvers "+
			"guard is dead code", resolveStageName)
	}
}

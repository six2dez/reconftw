//go:build realtools

// SPDX-License-Identifier: MIT
//
// Network-dependent verification of the gf pattern sources.
//
// WHY THIS IS SEPARATE FROM gf_patterns_test.go. Those tests stub `git clone`,
// so they prove the copy/merge logic and nothing about the world: a renamed
// repo, a moved subdirectory, or an upstream that stops shipping a gated class
// would leave them all green while every real install came out with an empty
// ~/.gf. That is the exact shape of false green this repo keeps paying for, and
// it is only catchable by actually cloning.
//
// It is REQUIRED to be network-capable, so it lives behind the realtools tag
// rather than in a ring that must pass offline.

package installer

import (
	"context"
	"testing"
)

// Every class health-check gates on must be obtainable from the REAL sources.
// A failure here means `reconftw install` would finish non-zero on a clean box:
// gf is a critical tool, so an ungated-but-missing pattern fails the install.
func TestRealtoolsGFPatternsCoverEveryGatedClass(t *testing.T) {
	dir := t.TempDir()
	orig := gfPatternDir
	gfPatternDir = func() string { return dir }
	t.Cleanup(func() { gfPatternDir = orig })

	if err := provisionGFPatterns(context.Background(), nil); err != nil {
		t.Fatalf("provisioning from the real upstream repos failed: %v\n"+
			"Every `reconftw install` would end here.", err)
	}
	missing := MissingGFPatterns()
	if len(missing) > 0 {
		t.Fatalf("the real sources do not supply gated class(es) %v.\n"+
			"health-check fails an install on these, so either a source moved/renamed "+
			"(fix gfPatternSources) or upstream stopped shipping them (move each to "+
			"GFUnobtainablePatterns WITH its reason, as `potential` already is).", missing)
	}
	t.Logf("REALTOOLS_RESOLVED: every gated gf class provisioned from upstream into %s", dir)
}

// The declared-unobtainable list must stay honest in the other direction: if a
// source starts shipping one of these, it should be gated, not excused.
func TestRealtoolsUnobtainableGFPatternsAreStillUnobtainable(t *testing.T) {
	if len(GFUnobtainablePatterns) == 0 {
		t.Skip("nothing declared unobtainable")
	}
	dir := t.TempDir()
	orig := gfPatternDir
	gfPatternDir = func() string { return dir }
	t.Cleanup(func() { gfPatternDir = orig })

	if err := provisionGFPatterns(context.Background(), nil); err != nil {
		t.Fatalf("provisioning failed: %v", err)
	}
	for class, reason := range GFUnobtainablePatterns {
		if patternPresent(dir, class) {
			t.Errorf("%q is declared unobtainable (%s) but upstream DOES ship it now — "+
				"move it into GFRequiredPatterns so health-check starts gating on it",
				class, reason)
		}
	}
}

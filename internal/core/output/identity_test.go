// Tests for CanonicalTargetID — acceptance gate 2 of Phase 15.
//
// The gate is stated as a SET-SIZE property, not as pairwise inequality: three
// structurally distinct targets must yield three distinct workspace slugs. A
// pairwise assertion between two of them passes even when the third still
// collides, which is precisely how F2 survived earlier review.
//
// External test package — the identity is exercised through its exported API.
package output_test

import (
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/output"
)

func mustID(t *testing.T, target string) output.TargetIdentity {
	t.Helper()
	id, err := output.CanonicalTargetID(target)
	if err != nil {
		t.Fatalf("CanonicalTargetID(%q): %v", target, err)
	}
	return id
}

// TestCanonicalTargetIDDistinctPrefixes is ACCEPTANCE GATE 2. /24, /16 and the
// bare IP with the same network address must not share a workspace.
func TestCanonicalTargetIDDistinctPrefixes(t *testing.T) {
	t.Parallel()

	targets := []string{"10.0.0.0/24", "10.0.0.0/16", "10.0.0.0"}
	set := make(map[string]string, len(targets))
	for _, tgt := range targets {
		id := mustID(t, tgt)
		if id.Slug == "" {
			t.Fatalf("CanonicalTargetID(%q): empty slug", tgt)
		}
		if prev, dup := set[id.Slug]; dup {
			t.Errorf("slug collision: %q and %q both map to %q", prev, tgt, id.Slug)
		}
		set[id.Slug] = tgt
	}
	if len(set) != len(targets) {
		t.Fatalf("gate 2 FAILED: %d targets produced %d distinct slugs: %v", len(targets), len(set), set)
	}
}

// TestCanonicalTargetIDKinds pins the three-way classification. The kind is
// part of the hashed identity, so getting it wrong silently changes every slug.
func TestCanonicalTargetIDKinds(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		wantKind      string
		wantCanonical string
	}{
		"example.com":   {output.KindDomain, "example.com"},
		"10.0.0.5":      {output.KindIP, "10.0.0.5"},
		"10.0.0.0/24":   {output.KindCIDR, "10.0.0.0/24"},
		"2001:db8::1":   {output.KindIP, "2001:db8::1"},
		"2001:db8::/32": {output.KindCIDR, "2001:db8::/32"},
	}
	for target, want := range cases {
		id := mustID(t, target)
		if id.Kind != want.wantKind {
			t.Errorf("CanonicalTargetID(%q).Kind = %q, want %q", target, id.Kind, want.wantKind)
		}
		if id.Canonical != want.wantCanonical {
			t.Errorf("CanonicalTargetID(%q).Canonical = %q, want %q", target, id.Canonical, want.wantCanonical)
		}
		if id.Raw != target {
			t.Errorf("CanonicalTargetID(%q).Raw = %q, want the input verbatim", target, id.Raw)
		}
	}
}

// TestCanonicalTargetIDMasksPrefix: a prefix whose host bits are set folds onto
// the same identity as its masked form. Without Masked(), 10.0.0.5/16 and
// 10.0.0.0/16 would be two workspaces for one engagement.
func TestCanonicalTargetIDMasksPrefix(t *testing.T) {
	t.Parallel()

	unmasked := mustID(t, "10.0.0.5/16")
	masked := mustID(t, "10.0.0.0/16")
	if unmasked.Slug != masked.Slug {
		t.Errorf("10.0.0.5/16 slug = %q, 10.0.0.0/16 slug = %q; want identical (Masked())", unmasked.Slug, masked.Slug)
	}
	if unmasked.Canonical != "10.0.0.0/16" {
		t.Errorf("10.0.0.5/16 canonical = %q, want %q", unmasked.Canonical, "10.0.0.0/16")
	}
}

// TestCanonicalTargetIDIPv6Distinct: an IPv6 prefix and an address inside it
// are different identities, and neither slug is empty.
func TestCanonicalTargetIDIPv6Distinct(t *testing.T) {
	t.Parallel()

	prefix := mustID(t, "2001:db8::/32")
	addr := mustID(t, "2001:db8::1")
	if prefix.Slug == addr.Slug {
		t.Errorf("2001:db8::/32 and 2001:db8::1 share slug %q", prefix.Slug)
	}
	if prefix.Slug == "" || addr.Slug == "" {
		t.Errorf("empty slug: prefix=%q addr=%q", prefix.Slug, addr.Slug)
	}
}

// TestCanonicalTargetIDUnmapsV4Mapped: ::ffff:10.0.0.1 is the same host as
// 10.0.0.1 and must not get its own workspace.
func TestCanonicalTargetIDUnmapsV4Mapped(t *testing.T) {
	t.Parallel()

	mapped := mustID(t, "::ffff:10.0.0.1")
	plain := mustID(t, "10.0.0.1")
	if mapped.Slug != plain.Slug {
		t.Errorf("::ffff:10.0.0.1 slug = %q, 10.0.0.1 slug = %q; want identical (Unmap())", mapped.Slug, plain.Slug)
	}
}

// TestCanonicalTargetIDCaseAndSchemeFold: case, scheme and URL path are all
// normalised away, so the three spellings share one workspace.
func TestCanonicalTargetIDCaseAndSchemeFold(t *testing.T) {
	t.Parallel()

	variants := []string{"EXAMPLE.com", "example.com", "https://Example.COM/some/path"}
	first := mustID(t, variants[0])
	for _, v := range variants[1:] {
		got := mustID(t, v)
		if got.Slug != first.Slug {
			t.Errorf("CanonicalTargetID(%q).Slug = %q, want %q (same identity as %q)", v, got.Slug, first.Slug, variants[0])
		}
	}
	if first.Canonical != "example.com" {
		t.Errorf("canonical = %q, want %q", first.Canonical, "example.com")
	}
}

// TestCanonicalTargetIDTrailingDotFold is the fold that closes the
// domain-flavoured re-run of F2: appctx.NewTarget ACCEPTS "example.com.", so
// without an explicit root-label strip that form gets its own workspace, its
// own checkpoints.db and its own artefact tree.
func TestCanonicalTargetIDTrailingDotFold(t *testing.T) {
	t.Parallel()

	withDot := mustID(t, "example.com.")
	without := mustID(t, "example.com")
	if withDot.Slug != without.Slug {
		t.Errorf("example.com. slug = %q, example.com slug = %q; want identical", withDot.Slug, without.Slug)
	}
	if withDot.Canonical != without.Canonical {
		t.Errorf("example.com. canonical = %q, example.com canonical = %q; want identical", withDot.Canonical, without.Canonical)
	}

	// Exactly ONE dot is stripped: "example.com.." must stay a distinct string
	// (appctx.NewTarget rejects it outright).
	twoDots := mustID(t, "example.com..")
	if twoDots.Canonical == without.Canonical {
		t.Errorf("example.com.. folded onto example.com; only ONE root label may be stripped")
	}
}

// TestCanonicalTargetIDRejectsEmpty covers the error branch.
func TestCanonicalTargetIDRejectsEmpty(t *testing.T) {
	t.Parallel()

	for _, in := range []string{"", "   ", "///", "https://"} {
		if _, err := output.CanonicalTargetID(in); err == nil {
			t.Errorf("CanonicalTargetID(%q) returned nil error; want a rejection", in)
		}
	}
}

// TestCanonicalTargetIDFoldsIDNToPunycode pins the IDNA contract: an
// internationalised hostname and its A-label form are ONE identity and must
// address ONE workspace. reconFTW targets IDN domains routinely, so the
// earlier reject-everything-non-ASCII behaviour made a legitimate target
// class unscannable; folding them apart would be worse still — two visually
// distinct spellings of the same engagement would grow two workspaces, two
// checkpoints.db files and two artefact trees, which is F2 in domain form.
func TestCanonicalTargetIDFoldsIDNToPunycode(t *testing.T) {
	t.Parallel()

	// Every spelling of the same registered name must collapse to one slug.
	forms := []string{"münchen.de", "MÜNCHEN.DE", "xn--mnchen-3ya.de", "münchen.de."}

	want, err := output.CanonicalTargetID(forms[0])
	if err != nil {
		t.Fatalf("CanonicalTargetID(%q): %v", forms[0], err)
	}
	if want.Canonical != "xn--mnchen-3ya.de" {
		t.Fatalf("canonical = %q; want the punycode A-label xn--mnchen-3ya.de", want.Canonical)
	}

	for _, in := range forms[1:] {
		got, err := output.CanonicalTargetID(in)
		if err != nil {
			t.Fatalf("CanonicalTargetID(%q): %v", in, err)
		}
		if got.Slug != want.Slug {
			t.Errorf("CanonicalTargetID(%q).Slug = %q; want %q — every spelling of one registered name must share a workspace",
				in, got.Slug, want.Slug)
		}
	}

	// A distinct IDN must stay distinct.
	other, err := output.CanonicalTargetID("köln.de")
	if err != nil {
		t.Fatalf("CanonicalTargetID(köln.de): %v", err)
	}
	if other.Slug == want.Slug {
		t.Error("two different IDN targets collapsed to one slug")
	}
}

// TestCanonicalTargetIDRejectsInvalidIDN pins the other half of the contract:
// for names that actually carry non-ASCII runes, idna.Lookup is the strict
// registration profile, so a structurally invalid label is refused rather
// than slugified into a neighbouring workspace.
func TestCanonicalTargetIDRejectsInvalidIDN(t *testing.T) {
	t.Parallel()

	// U+0301 COMBINING ACUTE ACCENT as the leading rune is invalid.
	if _, err := output.CanonicalTargetID("\u0301abc.de"); err == nil {
		t.Error("CanonicalTargetID accepted an IDNA-invalid leading combining mark; want rejection")
	}
}

// TestCanonicalTargetIDASCIIUnaffectedByIDNA pins the blast radius of the
// IDNA fold. idna.Lookup's registration profile rejects underscores and
// leading/trailing hyphens; this layer has always accepted them and hostname
// syntax is appctx.NewTarget's boundary, not this function's. Applying IDNA
// unconditionally would silently make previously scannable ASCII targets
// unaddressable.
func TestCanonicalTargetIDASCIIUnaffectedByIDNA(t *testing.T) {
	t.Parallel()

	for _, in := range []string{"a_b.de", "-lead.de", "trail-.de", "_dmarc.example.com"} {
		id, err := output.CanonicalTargetID(in)
		if err != nil {
			t.Errorf("CanonicalTargetID(%q) = %v; pure-ASCII input must not be subjected to IDNA validation", in, err)
			continue
		}
		if id.Canonical != strings.ToLower(in) {
			t.Errorf("CanonicalTargetID(%q).Canonical = %q; ASCII input must pass through unchanged", in, id.Canonical)
		}
	}
}

// TestCanonicalTargetIDSlugIsPathSafe is T-15-01-02: a traversal-shaped target
// can never produce a slug containing a separator or a ".." segment.
func TestCanonicalTargetIDSlugIsPathSafe(t *testing.T) {
	t.Parallel()

	for _, in := range []string{"../../etc", "..%2f..", `..\..\windows`, "foo;rm -rf /", "...."} {
		id, err := output.CanonicalTargetID(in)
		if err != nil {
			continue // refusing outright is also safe
		}
		if strings.ContainsAny(id.Slug, `/\`) {
			t.Errorf("CanonicalTargetID(%q).Slug = %q contains a path separator", in, id.Slug)
		}
		if id.Slug == "." || id.Slug == ".." {
			t.Errorf("CanonicalTargetID(%q).Slug = %q is a relative path segment", in, id.Slug)
		}
		if strings.HasPrefix(id.Slug, ".") {
			t.Errorf("CanonicalTargetID(%q).Slug = %q starts with a dot (hidden directory)", in, id.Slug)
		}
	}
}

// TestCanonicalTargetIDSlugShape pins the "<readable>-<hash8>" format so a
// later refactor cannot silently change the on-disk contract.
func TestCanonicalTargetIDSlugShape(t *testing.T) {
	t.Parallel()

	id := mustID(t, "example.com")
	idx := strings.LastIndexByte(id.Slug, '-')
	if idx < 0 {
		t.Fatalf("slug %q has no hash separator", id.Slug)
	}
	readable, hash := id.Slug[:idx], id.Slug[idx+1:]
	if readable != "example.com" {
		t.Errorf("readable component = %q, want %q", readable, "example.com")
	}
	if len(hash) != 8 {
		t.Errorf("hash component = %q (len %d), want 8 hex chars", hash, len(hash))
	}
	for _, r := range hash {
		if !strings.ContainsRune("0123456789abcdef", r) {
			t.Errorf("hash component %q is not lowercase hex", hash)
			break
		}
	}
}

// TestCanonicalTargetIDReadableBounded: a very long hostname still produces a
// bounded directory name.
func TestCanonicalTargetIDReadableBounded(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("a", 200) + ".com"
	id := mustID(t, long)
	if len(id.Slug) > 48+1+8 {
		t.Errorf("slug %q is %d chars, want <= %d", id.Slug, len(id.Slug), 48+1+8)
	}
}

// TestCanonicalTargetIDStable: the identity is a pure function — repeated calls
// return the same slug. This is what preserves checkpoints.db resume.
func TestCanonicalTargetIDStable(t *testing.T) {
	t.Parallel()

	for _, in := range []string{"example.com", "10.0.0.0/24", "2001:db8::1"} {
		a, b := mustID(t, in), mustID(t, in)
		if a.Slug != b.Slug {
			t.Errorf("CanonicalTargetID(%q) is not deterministic: %q vs %q", in, a.Slug, b.Slug)
		}
	}
}

// TestLegacyTargetSlug pins the OLD sanitizeTargetName behaviour that
// adoptLegacyWorkspace must be able to find on disk. If this drifts, adoption
// silently stops matching pre-upgrade directories.
func TestLegacyTargetSlug(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"example.com":                   "example.com",
		"EXAMPLE.com":                   "example.com",
		"https://Example.COM/some/path": "example.com",
		"10.0.0.0/24":                   "10.0.0.0",
		"10.0.0.0/16":                   "10.0.0.0",
		"10.0.0.0":                      "10.0.0.0",
		"foo;rm -rf /":                  "foo_rm_-rf",
		"///":                           "",
	}
	for in, want := range cases {
		if got := output.LegacyTargetSlug(in); got != want {
			t.Errorf("LegacyTargetSlug(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestLegacyTargetSlugCollapsesPrefixes documents WHY adoption must refuse
// IP/CIDR targets that carry no identity marker: the old slug is many-to-one.
func TestLegacyTargetSlugCollapsesPrefixes(t *testing.T) {
	t.Parallel()

	a := output.LegacyTargetSlug("10.0.0.0/24")
	b := output.LegacyTargetSlug("10.0.0.0/16")
	c := output.LegacyTargetSlug("10.0.0.0")
	if a != b || b != c {
		t.Fatalf("legacy slugs unexpectedly distinct: %q %q %q — the ambiguity precondition assumes they collapse", a, b, c)
	}
}

// Canonical target identity — the workspace-addressing primitive (F2).
//
// Source:
//   - 15-CONTEXT.md F2 ("Workspaces collide across different targets"): the
//     pre-Phase-15 sanitizeTargetName split the target on the first '/', so
//     10.0.0.0/24, 10.0.0.0/16 and the bare IP 10.0.0.0 all collapsed onto the
//     single workspace name "10.0.0.0" — one inputs/, one artefacts/, one
//     checkpoints.db shared by three structurally distinct engagements. That is
//     an information-disclosure defect, not a cosmetic one: engagement A's
//     findings surface in engagement B's artefacts and reports.
//   - 15-PATTERNS.md §A3 ("Canonical target identity").
//
// The fix is an identity that preserves BOTH the target's kind (domain / IP /
// CIDR) AND its full canonical form, folded into the directory name via a hash
// suffix that survives slug sanitization. `/` becomes `_` in the readable part,
// so the readable part alone can still collide; the hash is what cannot.
package output

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// Target kinds. The kind is part of the hashed identity, so a hostname that
// happens to sanitize to the same readable form as an address still lands in
// its own workspace.
const (
	KindDomain = "domain"
	KindIP     = "ip"
	KindCIDR   = "cidr"
)

// slugReadableMax caps the human-readable component of a workspace slug.
// Bounds the directory-name length for very long hostnames (the 253-octet
// cap enforced by appctx.NewTarget is still far longer than is browsable).
const slugReadableMax = 48

// slugHashLen is the number of hex characters of the SHA-256 identity digest
// appended to the readable component. 8 hex chars = 32 bits; workspace slugs
// are compared for equality, never brute-forced, so this is a readability /
// accidental-collision tradeoff, not a security parameter.
const slugHashLen = 8

// targetSanitizerRe matches any character NOT in the canonical
// "letters / digits / dot / dash / underscore" set. Replaced with `_`.
//
// This is the ONLY transformation applied to the readable slug component, which
// is what makes path traversal structurally impossible: `/`, `\` and every other
// separator are replaced before the string ever reaches filepath.Join
// (T-15-01-02).
var targetSanitizerRe = regexp.MustCompile(`[^a-z0-9._-]+`)

// TargetIdentity is the type-preserving identity of a scan target. It is the
// sole input to the workspace directory name and is persisted verbatim into
// <workspace>/.target-identity.json so a later run (or an operator) can tell
// which engagement a directory belongs to.
type TargetIdentity struct {
	// Raw is the operator input exactly as given (pre-normalisation).
	Raw string `json:"raw"`
	// Canonical is the normalised form: a masked prefix for CIDRs, an unmapped
	// address for IPs, a lowercased/root-label-stripped hostname for domains.
	Canonical string `json:"canonical"`
	// Kind is one of KindDomain, KindIP, KindCIDR.
	Kind string `json:"kind"`
	// Slug is the directory-safe workspace name: "<readable>-<hash8>".
	Slug string `json:"slug"`
}

// CanonicalTargetID normalises an operator-supplied target into a
// type-preserving identity whose Slug is safe to use as a directory name.
//
// Normalisation order:
//
//  1. Trim whitespace, strip a leading "https://" / "http://".
//  2. Drop everything from the first '/' ONLY when the remainder does not parse
//     as a CIDR prefix. A '/' that carries a prefix length must survive (that
//     was exactly the F2 data-loss bug); a '/' that starts a URL path must not.
//  3. CIDR: netip.ParsePrefix + Masked(), so 10.0.0.5/16 and 10.0.0.0/16 are
//     one identity while /24 and /16 are two.
//  4. IP: netip.ParseAddr + Unmap(), so ::ffff:10.0.0.1 and 10.0.0.1 agree.
//  5. Domain: lowercase, strip exactly ONE trailing dot (the DNS root label),
//     ASCII-only guard (see the IDNA note below).
//
// IDNA NOTE (deliberate, recorded in 15-01-SUMMARY): golang.org/x/net is not a
// direct or indirect dependency of this module, and this plan is not permitted
// to add one. Rather than guess at a homograph-safe normalisation, non-ASCII
// hostnames are REJECTED. Silently slugifying them would let two visually
// identical targets address two different workspaces (or worse, one).
// Punycode input (xn--…) is already ASCII and is accepted unchanged.
//
// Hostname SYNTAX is deliberately NOT validated here — that is
// appctx.NewTarget's boundary responsibility. This function must stay callable
// on any string that reached the workspace layer.
func CanonicalTargetID(target string) (TargetIdentity, error) {
	raw := target

	s := strings.TrimSpace(target)
	if s == "" {
		return TargetIdentity{}, fmt.Errorf("output: CanonicalTargetID: empty target: %q", raw)
	}
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")

	// Step 2. ParsePrefix is the discriminator, not a heuristic on the string:
	// "10.0.0.0/24" keeps its slash, "example.com/some/path" loses it.
	if _, err := netip.ParsePrefix(s); err != nil {
		if idx := strings.IndexByte(s, '/'); idx >= 0 {
			s = s[:idx]
		}
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return TargetIdentity{}, fmt.Errorf("output: CanonicalTargetID: target has no host component: %q", raw)
	}

	var kind, canonical string
	switch {
	case isCIDRLiteral(s):
		p, err := netip.ParsePrefix(s)
		if err != nil { // unreachable: isCIDRLiteral just parsed it
			return TargetIdentity{}, fmt.Errorf("output: CanonicalTargetID: parse prefix: %q: %w", raw, err)
		}
		kind, canonical = KindCIDR, p.Masked().String()
	case isAddrLiteral(s):
		a, err := netip.ParseAddr(s)
		if err != nil { // unreachable: isAddrLiteral just parsed it
			return TargetIdentity{}, fmt.Errorf("output: CanonicalTargetID: parse addr: %q: %w", raw, err)
		}
		kind, canonical = KindIP, a.Unmap().String()
	default:
		d, err := canonicalDomain(s)
		if err != nil {
			return TargetIdentity{}, fmt.Errorf("output: CanonicalTargetID: %w: %q", err, raw)
		}
		kind, canonical = KindDomain, d
	}

	return TargetIdentity{
		Raw:       raw,
		Canonical: canonical,
		Kind:      kind,
		Slug:      targetSlug(kind, canonical),
	}, nil
}

// isCIDRLiteral reports whether s parses as an IP prefix.
func isCIDRLiteral(s string) bool {
	_, err := netip.ParsePrefix(s)
	return err == nil
}

// isAddrLiteral reports whether s parses as a bare IP address.
func isAddrLiteral(s string) bool {
	_, err := netip.ParseAddr(s)
	return err == nil
}

// canonicalDomain lowercases, strips the DNS root label and enforces the ASCII
// carve-out documented on CanonicalTargetID.
//
// The trailing-dot strip is explicit and MUST happen here: appctx.NewTarget
// accepts "example.com." (a syntactically valid absolute name), so without this
// fold that form would open its OWN workspace with its own checkpoints.db and
// its own artefact tree — a domain-flavoured re-run of F2. Exactly ONE dot is
// stripped, so "example.com.." stays a distinct (and appctx-rejected) string.
func canonicalDomain(s string) (string, error) {
	d := strings.ToLower(s)
	d = strings.TrimSuffix(d, ".")
	if d == "" {
		return "", fmt.Errorf("target normalised to empty")
	}
	for i := 0; i < len(d); i++ {
		if d[i] >= 0x80 {
			return "", fmt.Errorf("non-ASCII hostname rejected (IDNA normalisation unavailable)")
		}
	}
	return d, nil
}

// targetSlug builds "<readable>-<hash8>".
//
// BOTH components are load-bearing. The readable part is what keeps the data
// dir browsable; the hash is what makes the identity injective. The sanitizer
// maps '/' to '_', so "10.0.0.0/24" and "10.0.0.0_24" have the same readable
// form — only the digest of (kind, canonical) separates them.
func targetSlug(kind, canonical string) string {
	sum := sha256.Sum256([]byte(kind + "\x00" + canonical))
	return readableSlug(canonical) + "-" + hex.EncodeToString(sum[:])[:slugHashLen]
}

// readableSlug produces the human-facing component of a workspace slug.
//
// Leading/trailing dots are trimmed alongside underscores (the old sanitizer
// trimmed only underscores): that keeps the slug from starting with '.' (a
// hidden directory) and makes it impossible for the readable component to be
// "." or ".." even before the hash suffix is appended (T-15-01-02).
func readableSlug(canonical string) string {
	s := strings.ToLower(canonical)
	s = targetSanitizerRe.ReplaceAllString(s, "_")
	for strings.Contains(s, "__") {
		s = strings.ReplaceAll(s, "__", "_")
	}
	s = strings.Trim(s, "_.")
	s = truncateRunes(s, slugReadableMax)
	s = strings.Trim(s, "_.")
	if s == "" {
		// Everything was punctuation. The hash suffix still makes the slug
		// unique; this only supplies a stable, non-empty prefix.
		s = "target"
	}
	return s
}

// truncateRunes cuts s to at most n runes (never mid-rune).
func truncateRunes(s string, n int) string {
	count := 0
	for i := range s {
		if count == n {
			return s[:i]
		}
		count++
	}
	return s
}

// LegacyTargetSlug returns EXACTLY what the pre-Phase-15 sanitizeTargetName
// produced for the same input. The body is moved verbatim, not reimplemented:
// adoptLegacyWorkspace uses it to locate a workspace written by an older
// release, and an approximation would either miss real directories or claim
// directories that belong to a different engagement.
//
// Keeping it exported and pinned by a test is what makes the adoption step
// auditable rather than a guess about what the old code emitted.
//
// Strategy (matched the v1 sanitize_domain intent):
//
//  1. Strip leading "http://" / "https://" scheme prefix.
//  2. Drop URL path and trailing components (split on first "/") — this is the
//     F2 bug itself, preserved here on purpose.
//  3. Lowercase.
//  4. Trim leading/trailing whitespace.
//  5. Replace any remaining non-alphanumeric (excluding `.-_`) with `_`.
//  6. Collapse repeated `_` and trim leading/trailing `_`.
func LegacyTargetSlug(target string) string {
	s := strings.TrimSpace(target)
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	if idx := strings.IndexByte(s, '/'); idx >= 0 {
		s = s[:idx]
	}
	s = strings.ToLower(s)
	s = targetSanitizerRe.ReplaceAllString(s, "_")
	// Collapse repeated underscores.
	for strings.Contains(s, "__") {
		s = strings.ReplaceAll(s, "__", "_")
	}
	return strings.Trim(s, "_")
}

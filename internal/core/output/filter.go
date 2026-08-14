// filter.go — the aggregator side of the scope contract.
//
// Interface.Append is deliberately all-or-nothing: for a SINGLE-SOURCE Task
// write, one out-of-scope record is a bug worth surfacing, so the whole batch
// is rejected. That contract is wrong for MULTI-SOURCE aggregators, which glob
// every producer's staging file into one Append call — there, a single bad
// record from one scanner silently destroys every good record from all the
// others.
//
// Interface documents that aggregators must therefore drop noise BEFORE
// calling Append. Historically each aggregator hand-rolled that filter, and
// the copies drifted: web.urldedup lost 1108 URLs to an unfiltered batch, and
// every vulns finding was discarded because no copy existed at all.
//
// FilterInScope is the single implementation. It is defined here, next to
// Append, so it reuses the very same artefactScopeField / extractScopeValue
// the gate uses instead of mirroring them — a mirrored filter that drifts
// looser still lets Append reject the batch, and one that drifts stricter
// silently discards good findings.
package output

import (
	"encoding/json"
	"net/url"
)

// FilterInScope splits lines into those Append will accept for the given
// artefact and a count of those it would reject.
//
// Rejected: invalid JSON, a missing scope-checkable field, or a value outside
// the configured scope. Accepted unconditionally: artefacts with no scope
// dispatch entry (pass-through, e.g. notes) once the JSON parses, and
// company-seeded OSINT findings carrying neither host nor url (D-O1).
//
// A nil tree skips the membership check but still enforces JSON validity and
// locator presence, matching what Append does with a nil ScopeFilter.
func FilterInScope(tree Interface, artefact string, lines [][]byte) (kept [][]byte, dropped int) {
	scopeField := artefactScopeField(artefact)
	kept = make([][]byte, 0, len(lines))
	for _, line := range lines {
		if scopeField == "" {
			// Pass-through artefact: Append only requires valid JSON.
			if !json.Valid(line) {
				dropped++
				continue
			}
			kept = append(kept, line)
			continue
		}
		val, isURL, skipScope, err := extractScopeValue(line, scopeField)
		if err != nil || (!skipScope && val == "") {
			dropped++
			continue
		}
		if skipScope {
			kept = append(kept, line)
			continue
		}
		if tree != nil && !scopeAdmits(tree, val, isURL) {
			dropped++
			continue
		}
		kept = append(kept, line)
	}
	return kept, dropped
}

// scopeAdmits applies the membership check through Interface.InScope, which is
// all an aggregator is given. For URL-shaped values it reproduces
// DefaultScopeFilter.IsInScopeURL: parse, reject userinfo (SUBD-05), then
// scope-check the hostname.
func scopeAdmits(tree Interface, val string, isURL bool) bool {
	if !isURL {
		return tree.InScope(val)
	}
	u, err := url.Parse(val)
	if err != nil || u.User != nil || u.Hostname() == "" {
		return false
	}
	return tree.InScope(u.Hostname())
}

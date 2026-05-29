// Source: ADR 0002 §7 lines 1913-2054 (BINDING — failure_policy model).
//
// FailurePolicy is a per-module-group enum:
//   - PolicyBestEffort — sibling tasks continue when one errors; per-task
//     errors logged as warnings; stage returns nil.
//   - PolicyFailFast   — first error cancels all peers via errgroup.WithContext;
//     stage returns the first non-nil error.
//
// Defaults per ADR §7 + REQUIREMENTS.md FOUND-06:
//   - subdomains → fail_fast (spine — empty list breaks every downstream module)
//   - web/vulns/osint → best_effort (independent sources; partial coverage OK)
//
// Configuration override: [scheduler.overrides] in reconftw.toml. The
// Scheduler accepts a `map[string]FailurePolicy` and policyFor returns the
// override when present, falling back to the ADR-defined default.

package scheduler

// FailurePolicy controls how a stage handles task errors.
//
// Source: ADR §7 lines 1966-1979.
type FailurePolicy string

const (
	// PolicyBestEffort continues all sibling tasks when one errors.
	// Per-task errors are logged as warnings; the stage returns nil.
	// v1 analog: CONTINUE_ON_TOOL_ERROR=true + parallel_funcs for OSINT/vulns.
	PolicyBestEffort FailurePolicy = "best_effort"

	// PolicyFailFast cancels all sibling tasks when one errors.
	// Uses errgroup.WithContext — first error cancels the context for all peers.
	// v1 analog: recon() spine for subdomains (sequential dependencies).
	PolicyFailFast FailurePolicy = "fail_fast"
)

// policyFor returns the FailurePolicy for a given module group. The
// override map takes precedence; otherwise the ADR-defined defaults apply.
//
// Default rules (ADR §7):
//   - "subdomains", "scheduler" → PolicyFailFast (the spine)
//   - "web", "vulns", "osint"   → PolicyBestEffort (independent sources)
//   - anything else             → PolicyBestEffort (conservative — don't abort)
func policyFor(module string, override map[string]FailurePolicy) FailurePolicy {
	if override != nil {
		if p, ok := override[module]; ok {
			return p
		}
	}
	switch module {
	case "subdomains", "scheduler":
		return PolicyFailFast
	case "subdomains.passive", "subdomains.aux":
		// GAP-2 + live-run follow-up: independent-discovery and post-processing
		// groups run best-effort. A flaky/missing source (crt.sh timeout, an
		// uninstalled tool, analyticsrelationships panicking on a builtwith
		// error) must NOT abort the whole subs run — this mirrors bash v1, where
		// sub_passive/sub_scraping/sub_analytics/sub_ns_delegation, permutations,
		// and the takeover/buckets/asn/geo enrichment steps are all best-effort.
		//   - "subdomains.passive" → passive enumeration sources
		//   - "subdomains.aux"     → resolve-stage aux discovery (scraping/
		//     analytics/ns_delegation), permutations, and enrichment
		// Only the TRUE spine (active/brute/resolvers.health/dns/tls/srv,
		// module="subdomains") stays PolicyFailFast — an empty resolved set
		// breaks every downstream module. ScopeError/OutOfScope STILL
		// re-propagate even in best_effort (scheduler.go errors.Is(ErrScope)
		// guard is policy-keyed, not module-keyed).
		return PolicyBestEffort
	case "web", "vulns", "osint":
		return PolicyBestEffort
	default:
		return PolicyBestEffort
	}
}

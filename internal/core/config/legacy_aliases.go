// [legacy] table alias map — UPPER_CASE v1 names → v2-native koanf paths.
//
// Plan 02 ships the MECHANISM + a 5-entry test corpus per W18:
//   PARALLEL_MAX_JOBS, OSINT, SUBDOMAINS_GENERAL, SHODAN_API_KEY, AXIOM_FLEET_COUNT
//
// Phase 11 migrator owns the full ~290-entry enumeration. Rationale: Phase 3
// is the kernel — the alias map is migration content, not kernel structure.

package config

// legacyAliasMap is the static lookup table for [legacy] keys.
// Phase 11 migrator extends this map in a future plan; Plan 02 provides
// just enough entries to verify the mechanism end-to-end.
var legacyAliasMap = map[string]string{
	// W18 5-entry corpus (verified by TestLegacyAliasResolution):
	"PARALLEL_MAX_JOBS":  "concurrency.max_jobs",
	"OSINT":              "osint.enabled",
	"SUBDOMAINS_GENERAL": "subdomains.enabled",
	"SHODAN_API_KEY":     "api_keys.shodan",
	"AXIOM_FLEET_COUNT":  "axiom.fleet_count",
	// A handful of additional entries to make the mechanism useful for
	// downstream tests (Phase 4 module ports will likely add more).
	"PARALLEL_LOG_MODE":  "concurrency.log_mode",
	"WEBPROBEFULL":       "web.probe.enabled",
	"HTTPX_RATELIMIT":    "web.probe.rate_limit",
	"NUCLEICHECK":        "web.nuclei.enabled",
	"NUCLEI_RATELIMIT":   "web.nuclei.rate_limit",
	"NUCLEI_SEVERITY":    "web.nuclei.severity",
	"FUZZ":               "web.fuzz.enabled",
	"VULNS_GENERAL":      "vulns.enabled",
	"XSS":                "vulns.xss.enabled",
	"SQLI":               "vulns.sqli.enabled",
	"NOTIFICATION":       "notifications.enabled",
	"AXIOM_FLEET_NAME":   "axiom.fleet_name",
	"AXIOM_FLEET_REGIONS": "axiom.fleet_regions",
	"OUTPUT_VERBOSITY":   "output.verbosity",
	"DEEP":               "advanced.deep",
	"DIFF":               "advanced.diff",
}

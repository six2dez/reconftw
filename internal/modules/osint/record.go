// record.go — OSINTFindingRecord schema struct (D-O4).
//
// Source analog: internal/modules/vulns/gf.go:88-100 (VulnFindingRecord).
// OSINTFindingRecord extends the Phase 4/5/6 SARIF-compatible findings shape,
// adding the "informational" severity level (the ONLY findings-schema enum
// extension — D-O4) plus osint-specific fields. May ADD fields, never remove.
package osint

// OSINTFindingRecord is the Phase 7 extended findings.jsonl SARIF-compatible
// schema. It lets non-security OSINT records (a DNS TXT record, an email, an
// ASN, a CMS fingerprint) coexist with true security findings (leaked secrets,
// exposed cloud buckets, Postman/Swagger leaks, spoofable domains) in the
// single uniform findings.jsonl stream (D-O3), without bending informational
// data into a "vuln" shape — SARIF consumers (Phase 10) filter by level.
//
// XCUT-07 contract: ValueRedacted and PoCRedacted MUST have any secret values
// (leaked tokens, API keys, OOB callbacks) stripped before write. The
// secret-emitting Tasks (github_leaks, github_actions, postman, swagger) set
// only these *Redacted fields; the raw value is NEVER propagated to artefacts.
//
// Fields tagged omitempty are absent when not applicable.
type OSINTFindingRecord struct {
	// Phase 4/5 inherited SARIF-compatible fields.
	// Severity enum extended with "informational" (D-O4):
	//   critical | high | medium | low | info | informational
	Severity   string   `json:"severity,omitempty"`
	Confidence string   `json:"confidence,omitempty"`
	References []string `json:"references,omitempty"`

	// OSINT additions (omitempty = absent when N/A).
	Class         string `json:"class,omitempty"`          // "osint" (D-O3 tag)
	Source        string `json:"source,omitempty"`         // domain_info|ip_info|github_leaks|…
	Category      string `json:"category,omitempty"`       // dns-txt|email|asn|cms|leaked-secret|…
	ValueRedacted string `json:"value_redacted,omitempty"` // XCUT-07 where secret
	PoCRedacted   string `json:"poc_redacted,omitempty"`   // XCUT-07
}

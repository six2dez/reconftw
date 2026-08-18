// monitor_state_export_test.go — white-box exports for MonitorState's
// fingerprint helpers. Compiled only in test mode (package handlers).
//
// Kept separate from export_test.go so the persistent-state store and its tests
// form a self-contained unit: monitor_state.go, monitor_state_test.go and this
// file compile together without depending on the loop rewrite in monitor.go.
package handlers

// ExportedFindingFingerprint exposes findingFingerprint for testing.
func ExportedFindingFingerprint(templateSig, severity, host, locator string) string {
	return findingFingerprint(templateSig, severity, host, locator)
}

// ExportedFindingHostFromLocator exposes findingHostFromLocator for testing.
func ExportedFindingHostFromLocator(raw string) string {
	return findingHostFromLocator(raw)
}

// ExportedNormalizeFindingLocator exposes normalizeFindingLocator for testing.
func ExportedNormalizeFindingLocator(raw string) string {
	return normalizeFindingLocator(raw)
}

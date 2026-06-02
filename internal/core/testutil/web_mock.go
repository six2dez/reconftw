// web_mock.go — NewWebMockBackend: fixture helper for Phase-5 web parity tests.
//
// Provides a convenience constructor that loads web fixtures from a given
// fixtures directory path, mirroring the Phase-4 NewMockBackend signature.
//
// Usage in parity_test.go:
//
//	mb := testutil.NewWebMockBackend("/path/to/testdata/fixtures", "hackerone.com", 4)
//
// Source: .planning/phases/05-web-pipeline-e2e/05-06-PLAN.md Task 1.
package testutil

// NewWebMockBackend returns a MockBackend configured to serve web pipeline
// fixtures from fixturesDir. The scenario parameter selects which fixture
// file is returned per tool (e.g. "hackerone.com" → <tool>/hackerone.com.txt).
// capacity sets the Capacity() return value; <=0 defaults to 4.
//
// This is a thin wrapper over NewMockBackend with the same signature shape so
// parity_test.go in the web package reads identically to parity_test.go in
// the subdomains package.
func NewWebMockBackend(fixturesDir, scenario string, capacity int) *MockBackend {
	return NewMockBackend(MockBackendConfig{
		FixturesDir: fixturesDir,
		Scenario:    scenario,
		Capacity:    capacity,
	})
}

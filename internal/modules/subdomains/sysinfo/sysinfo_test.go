// sysinfo_test.go — TDD RED tests for MemProvider interface + OSMemProvider.
//
// Source: .planning/phases/04-subdomains-e2e-axiom-integration/04-04-PLAN.md Task 1.
package sysinfo_test

import (
	"testing"

	"github.com/six2dez/reconftw/internal/modules/subdomains/sysinfo"
)

// -------------------------------------------------------------------------
// Test 1: OSMemProvider.Available() returns > 0 on the test host
// -------------------------------------------------------------------------

// TestOSMemProviderReturnsPositive verifies that OSMemProvider.Available()
// returns a positive value on the test host. This is an integration smoke
// test — if the host genuinely has 0 bytes free the test will fail, which is
// the desired signal (the provider is working but the host is out of memory).
func TestOSMemProviderReturnsPositive(t *testing.T) {
	p := sysinfo.OSMemProvider{}
	got := p.Available()
	if got == 0 {
		t.Errorf("OSMemProvider.Available() = 0; expected >0 on a healthy test host")
	}
	t.Logf("OSMemProvider.Available() = %d bytes (%.2f GiB)", got, float64(got)/(1<<30))
}

// -------------------------------------------------------------------------
// Test 2: stub MemProvider returning 0 correctly simulates "no memory"
// -------------------------------------------------------------------------

// TestStubMemProviderZero verifies that a MemProvider returning 0 bytes
// satisfies the interface and correctly models the "no memory available" case.
func TestStubMemProviderZero(t *testing.T) {
	var p sysinfo.MemProvider = stubMemProvider(0)
	if got := p.Available(); got != 0 {
		t.Errorf("stubMemProvider(0).Available() = %d, want 0", got)
	}
}

// -------------------------------------------------------------------------
// Test 3: MemProvider interface satisfaction
// -------------------------------------------------------------------------

// TestMemProviderInterfaceSatisfied verifies that both OSMemProvider and a
// stub implementation satisfy the MemProvider interface at compile time and
// at runtime. The compile-time check uses interface assignment; the runtime
// check exercises the interface method.
func TestMemProviderInterfaceSatisfied(t *testing.T) {
	// Compile-time: both must satisfy MemProvider without conversion errors.
	var _ sysinfo.MemProvider = sysinfo.OSMemProvider{}
	var _ sysinfo.MemProvider = stubMemProvider(0)
	var _ sysinfo.MemProvider = stubMemProvider(1024 * 1024 * 1024) // 1 GiB

	// Runtime: call via interface — ensure dispatch works.
	providers := []sysinfo.MemProvider{
		sysinfo.OSMemProvider{},
		stubMemProvider(0),
		stubMemProvider(2 * 1024 * 1024 * 1024), // 2 GiB
	}
	for i, p := range providers {
		_ = p.Available()
		t.Logf("provider[%d].Available() called OK", i)
	}
}

// -------------------------------------------------------------------------
// Test 4: MemAvailable() package-level function uses OSMemProvider
// -------------------------------------------------------------------------

// TestMemAvailableFunction verifies the package-level MemAvailable() wrapper
// returns the same class of value as OSMemProvider.Available() (positive on
// healthy host). This ensures the default production path works without
// constructing a provider.
func TestMemAvailableFunction(t *testing.T) {
	got := sysinfo.MemAvailable()
	if got == 0 {
		t.Errorf("sysinfo.MemAvailable() = 0; expected >0 on a healthy test host")
	}
	t.Logf("sysinfo.MemAvailable() = %d bytes (%.2f GiB)", got, float64(got)/(1<<30))
}

// -------------------------------------------------------------------------
// Stub helper
// -------------------------------------------------------------------------

// stubMemProvider is a MemProvider that always returns a fixed value.
// Used to simulate low-memory or no-memory conditions in tests.
type stubMemProvider uint64

func (s stubMemProvider) Available() uint64 { return uint64(s) }

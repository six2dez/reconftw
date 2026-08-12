// Package sysinfo provides OS-level memory availability metrics for the
// reconFTW v2 subdomain permutation back-pressure gate (SUBD-03).
//
// REVIEWS FINDING — Memory back-pressure source:
// runtime.ReadMemStats().Sys - runtime.ReadMemStats().Alloc = Go heap
// reservation delta. This is NOT OS free RAM. It reflects the Go runtime's
// own heap allocation pattern, not whether the host has free physical RAM.
//
// CORRECT APPROACH (this package):
// github.com/shirou/gopsutil/v3/mem.VirtualMemory().Available
// → On Linux: reads /proc/meminfo MemAvailable (free + reclaimable pages)
// → On macOS: uses vm_stat (pages free + inactive + speculative)
// → Both return true OS-level free memory (what the kernel would give a new alloc)
//
// Design: injectable MemProvider interface for testability.
//   - Tests inject a stubMemProvider with a fixed value.
//   - Production code calls MemAvailable() which uses OSMemProvider.
//   - OSMemProvider.Available() returns 0 on gopsutil error (conservative —
//     back-pressure gate engages on error, preventing OOM from proceeding).
//
// Source: .planning/phases/04-subdomains-e2e-axiom-integration/04-04-PLAN.md Task 1.
package sysinfo

import (
	"log/slog"

	"github.com/shirou/gopsutil/v3/mem"
)

// MemProvider is the injectable interface for OS available-memory queries.
// The single Available() method returns the number of bytes the OS considers
// immediately available for allocation without swapping.
//
// Implementations:
//   - OSMemProvider — production; calls gopsutil mem.VirtualMemory().Available
//   - stub (test-only) — returns a fixed uint64 value for deterministic tests
type MemProvider interface {
	// Available returns the number of bytes of OS available memory.
	// Returns 0 on error (conservative: back-pressure will engage).
	Available() uint64
}

// OSMemProvider is the production MemProvider implementation.
// It calls github.com/shirou/gopsutil/v3/mem.VirtualMemory().Available to
// obtain the true OS-level available memory, NOT runtime.ReadMemStats.
type OSMemProvider struct{}

// Available calls gopsutil mem.VirtualMemory() and returns Available bytes.
// On any error (rare: platform call failed), logs at Warn level and returns 0
// so the caller's back-pressure gate engages conservatively (safe: we don't
// proceed when we don't know the memory state).
//
// Do NOT use runtime.ReadMemStats here:
//
//	runtime.MemStats.Sys - runtime.MemStats.Alloc = Go heap reservation delta
//	That is NOT OS free memory. gopsutil is correct (REVIEWS finding fix).
func (OSMemProvider) Available() uint64 {
	vmStat, err := mem.VirtualMemory()
	if err != nil {
		// Conservative fallback: 0 → back-pressure gate will engage.
		// This is intentional: failing to read memory stats means we
		// cannot guarantee enough free RAM; safer to back-pressure than OOM.
		slog.Warn("sysinfo: gopsutil VirtualMemory failed; returning 0 (conservative)",
			"error", err.Error())
		return 0
	}
	return vmStat.Available
}

// MemAvailable returns the number of available OS bytes using the default
// production OSMemProvider. This is the package-level convenience function
// used by permutation tasks when they do not need to inject a custom provider.
//
// Equivalent to OSMemProvider{}.Available() — kept as a named function for
// callers that do not need interface injection (simpler call site).
func MemAvailable() uint64 {
	return OSMemProvider{}.Available()
}

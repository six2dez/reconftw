// SPDX-License-Identifier: MIT
//
// Test-only exports. Keeping these in an _test.go file means the identifiers
// exist for the external backend_test package WITHOUT widening the production
// API — the module map and the not-ported list stay unexported to real callers.

package backend

// AxiomModuleNamesForTest returns the tool names that have a NON-EMPTY axiom
// module, i.e. the set that can actually be dispatched to a fleet. A name mapped
// to "" is local by declaration and is deliberately excluded.
func AxiomModuleNamesForTest() map[string]bool {
	out := make(map[string]bool)
	for _, module := range defaultAxiomModuleMap() {
		if module != "" {
			out[module] = true
		}
	}
	return out
}

// AxiomModulesNotPortedForTest exposes the declared v1-module gap with reasons.
func AxiomModulesNotPortedForTest() map[string]string {
	out := make(map[string]string, len(axiomModulesNotPorted))
	for k, v := range axiomModulesNotPorted {
		out[k] = v
	}
	return out
}

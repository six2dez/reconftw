// SPDX-License-Identifier: MIT
// Spike PoC — DO NOT EVOLVE INTO PRODUCTION
// Source: .planning/phases/01-language-adr-spike/01-02-PLAN.md
// Locked scope: spike/README.md §Scope
package tests

import "os/exec"

// lookPath returns true if the named binary is available on PATH.
func lookPath(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

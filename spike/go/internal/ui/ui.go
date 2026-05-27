// SPDX-License-Identifier: MIT
// Spike PoC — DO NOT EVOLVE INTO PRODUCTION
// Source: .planning/phases/01-language-adr-spike/01-02-PLAN.md Task 3
// Locked scope: spike/README.md §Scope
// Pattern reference: .planning/phases/01-language-adr-spike/01-RESEARCH.md §3.1
// Mirror of bash lib/ui.sh's _print_status pattern — simplified for spike throwaway scope.
package ui

import (
	"fmt"
	"os"
)

// Info prints an informational message to stderr.
// Format: [INFO] <msg>
func Info(msg string) {
	fmt.Fprintln(os.Stderr, "[INFO] "+msg)
}

// Skip prints a skip message to stderr with component and reason.
// Format: [SKIP] <component>: <reason>
// T-01-02-SI-02: explicitly does NOT echo env var contents.
func Skip(component, reason string) {
	fmt.Fprintln(os.Stderr, "[SKIP] "+component+": "+reason)
}

// Warn prints a warning message to stderr.
// Format: [WARN] <msg>
func Warn(msg string) {
	fmt.Fprintln(os.Stderr, "[WARN] "+msg)
}

// Err prints an error message to stderr.
// Format: [ERR ] <msg>
func Err(msg string) {
	fmt.Fprintln(os.Stderr, "[ERR ] "+msg)
}

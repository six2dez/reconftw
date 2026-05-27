// SPDX-License-Identifier: MIT
// Spike PoC — DO NOT EVOLVE INTO PRODUCTION
// Source: .planning/phases/01-language-adr-spike/01-02-PLAN.md
// Locked scope: spike/README.md §Scope
// Pattern reference: .planning/phases/01-language-adr-spike/01-RESEARCH.md §3.1
// Stub ui functions for Task 1; real implementation in Task 3 (Plan 01-02 Task 3).
package ui

// Info prints an informational message to stderr.
func Info(msg string) {}

// Skip prints a skip message to stderr with component and reason.
func Skip(component, reason string) {}

// Warn prints a warning message to stderr.
func Warn(msg string) {}

// Err prints an error message to stderr.
func Err(msg string) {}

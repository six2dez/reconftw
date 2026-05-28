// SPDX-License-Identifier: MIT
// Compile-only build target for ADR 0002 pre-sign gate (D-14).
// Source: .planning/decisions/0002-architecture-v2.md §11 Pre-Sign Verification Gate
// Reference: .planning/phases/02-architecture-v2-design/02-RESEARCH.md §Pre-Sign Verification Gate
// DO NOT import into production code. This package exists solely for `go build ./interfaces_check/...`.
package main

import "fmt"

func main() { fmt.Println("interfaces_check: compile gate — DO NOT RUN") }

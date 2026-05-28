#!/usr/bin/env bash
set -euo pipefail

ADR=".planning/decisions/0002-architecture-v2.md"

echo "=== Check 1: ARCH-NN requirement coverage ==="
for req in ARCH-01 ARCH-02 ARCH-03 ARCH-04 ARCH-05 ARCH-06 ARCH-07 ARCH-08 ARCH-09 ARCH-10 ARCH-11 ARCH-12; do
    if ! grep -q "$req" "$ADR"; then
        echo "FAIL: $req not found in ADR"
        exit 1
    fi
    echo "  OK: $req found"
done

echo "=== Check 2: TOML blocks parse as valid TOML ==="
# Extract all ```toml code blocks and parse each
grep -n '```toml' "$ADR" | while read -r line; do
    block_start=$(echo "$line" | cut -d: -f1)
    # Extract to temp file and validate with tomljson
    awk "NR==$((block_start+1)),/^\`\`\`/{if(/^\`\`\`/)exit;print}" "$ADR" | \
        tomljson > /dev/null && echo "  OK: TOML block at line $block_start" || \
        { echo "FAIL: TOML block at line $block_start"; exit 1; }
done

echo "=== Check 3: Go interface snippets compile ==="
# Phase 3 plan-01 moved this scaffold from interfaces_check/ to cmd/interfaces_check/
# so that `go build ./...` no longer collides with a same-named directory at repo root.
# Build to temp output as the existing Phase 2 pattern (binary not committed).
mkdir -p cmd/interfaces_check
go build -o /tmp/interfaces_check_verify ./cmd/interfaces_check/... && echo "  OK: Go snippets compile"

echo "=== Check 4: Glossary completeness ==="
# Every term in interface signatures must have a glossary entry
for term in AppContext Backend Task Result FailurePolicy Secret ToolError ToolTimeout OutOfScope AxiomFailure ConfigError ScopeError ChecksumMismatch; do
    if ! grep -q "\\b$term\\b" "$ADR"; then
        echo "FAIL: glossary missing term $term"
        exit 1
    fi
    echo "  OK: $term in glossary"
done

echo "=== ALL CHECKS PASSED — safe to sign ==="

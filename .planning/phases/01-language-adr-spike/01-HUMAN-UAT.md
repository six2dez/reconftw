---
status: partial
phase: 01-language-adr-spike
source: [01-VERIFICATION.md]
started: 2026-05-28T00:00:00Z
updated: 2026-05-28T00:00:00Z
---

## Current Test

[awaiting human judgment on item 1]

## Tests

### 1. M5 scale caveat acceptability
expected: Either (a) the ADR or measurement-worksheet.md explicitly states that DEC-03's 'RSS under 5K concurrent subdomain hosts' criterion was measured at ~36 subdomains (hackerone.com canonical target) due to the target's actual scale, and the roadmap downscoping is accepted as sufficient; OR (b) maintainer confirms the worksheet's inline table note '36 subdomains resolved; subfinder returned early' at Run 1 is adequate documentation of the scale caveat and no ADR amendment is needed.
result: [pending]
why_human: The ADR body has no text referencing "36", the measurement scale, or the roadmap downscoping of the 5K criterion. The worksheet's Raw Measurements table has an inline cell note but this is not a caveat entry. Maintainer call on whether this constitutes sufficient documentation.

### 2. Go binary rebuild confirmation
expected: Maintainer can run go build with `-trimpath -ldflags="-s -w"` and produce a working spike/go/bin/spike binary.
result: passed
notes: Built 2026-05-28 by orchestrator. `bin/spike` (3,046,450 bytes, Mach-O arm64) runs; prints usage and reports "required flag(s) target not set" — expected CLI behavior. DEC-02 "build and run on maintainer's machine" satisfied. Note: the verifier's command had `-trimpath` inside `-ldflags` which fails; the correct invocation is `go build -trimpath -ldflags="-s -w" -o bin/spike ./cmd/spike/`.

## Summary

total: 2
passed: 1
issues: 0
pending: 1
skipped: 0
blocked: 0

## Gaps

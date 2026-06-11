---
id: xcut07-l2-redactor-noop-noninteractive
title: L2 logger redactor is a no-op on non-live-UI paths (XCUT-07 backstop inert when piped/quiet/dry-run)
created: 2026-06-10
source: 07-REVIEW-GAPS.md WR-01 (Phase 7 gap-closure re-review)
area: core/log, core/ui (Boot)
severity: warning
exploitable: false
resolves_phase: ""
---

## Problem
`registerSecret(app.Log, value)` (the L2 redactor backstop for XCUT-07) is a **silent no-op**
whenever the logger is not the redacting handler. The redacting logger is only built in the
`liveUI` branch of `Boot`; on piped / `--quiet` / `--dry-run` / captured-to-file paths, `Boot`
falls back to a plain `slog.Default()`, so registered secrets are never scrubbed from log lines.

Codebase-wide (affects every secret-emitting task: github_leaks, trufflehog, gato, postman,
swagger), NOT a Phase 7 regression — pre-existing logger-architecture property surfaced by the
Phase 7 gato-auth gap fix.

## Why it's not currently exploitable
- L3 field-level redaction (`ValueRedacted="***"` in findings.jsonl) is always active — the
  primary guard holds.
- The one gato error sink (`ToolError.Error()`) formats Tool/ExitCode/Inner only; it never
  stringifies captured Stderr, so no token reaches the logged error today.

## Fix direction
Build the redacting handler unconditionally in `Boot` (wrap whatever sink is chosen — live UI,
plain stderr, or file), so `register_secret` works on every output path. Natural home:
`/gsd-secure-phase` XCUT-07 hardening, or a dedicated core/log task. Add a test asserting a
registered secret is scrubbed on the non-liveUI path.

## Related Info items (07-REVIEW-GAPS.md)
- gato temp file holds raw secrets in WorkDir (0600) during the run window.
- env-requiring gato runs increment the Failover kill-switch counter (matters only in composite modes).
- stage-order test helper assumes exact-name prefixes while production uses strings.HasPrefix.

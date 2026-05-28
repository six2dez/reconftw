# Test Fixtures

Fixture files consumed by `internal/core/testutil/MockBackend` to provide deterministic, subprocess-free tool output for Phase 4-7 module tests.

## Layout

```
fixtures/
  <tool-name>/
    <scenario>.txt    -- plain-text line-per-record (subfinder, anew, ...)
    <scenario>.jsonl  -- JSONL line-per-record (httpx, dnsx, ...)
```

`MockBackend.Exec` and `MockBackend.Stream` resolve the fixture path as
`<MockBackend.FixturesDir>/<tool.Name>/<MockBackend.Scenario>.txt` (with `.jsonl`
fallback when the `.txt` file is absent). The mock NEVER spawns a subprocess —
all tool output is read from fixture files.

## Seeded fixtures (Phase 3)

- `subfinder/example.com.txt` — 6 realistic subdomain lines used to validate
  the MockBackend → OutputTree path in `TestMockBackend_Exec_*` tests.
- `httpx/hosts.jsonl` — 3 JSONL records mirroring the real httpx schema
  (input/host/port/status_code/title/tech) used in
  `TestMockBackend_Stream_YieldsEventsForJSONL`.

## Adding new fixtures

When a Phase 4-7 plan needs a new fixture:

1. Place the fixture under `fixtures/<tool>/<scenario>.txt` (or `.jsonl`).
2. Reference it in the test via `mb.SetScenario("<scenario>")`.
3. Keep fixtures small (≤ 100 KiB) — large fixtures slow down `go test ./...`
   for every package that imports `testutil`.
4. Real-world tool output occasionally contains secret-shaped strings (API
   keys, internal IPs). Sanitize fixtures before committing — the XCUT-07
   sentinel test runs against every package and an unsanitized fixture would
   trip it.

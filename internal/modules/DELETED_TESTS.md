# Deleted tests

One line per test deleted on purpose, with what it asserted and why it went.
A test that is deleted silently is indistinguishable from one that never
existed; this file is the diff that a `git log` on a removed function cannot
give you.

## 21-04 — self-asserting tests

A self-assertion compares a value against a copy of itself (a map's length
against a constant typed from the map, a TOML number against a literal copied
from the TOML) or asserts nothing (only `t.Logf`). It cannot fail on a real
regression and its failure message tells the reader to edit the other copy.

| Test | File | Asserted | Why removed |
|---|---|---|---|
| `TestSilentSuccessCensus` | `internal/modules/silent_success_test.go` | nothing — printed the rule-B1 census via `t.Logf` | pure log; the numbers are available from `checkSilentSuccessFull` whenever someone wants them |
| `TestStreamContractAllowlistShrinks` | `internal/modules/stream_contract_test.go` | `len(streamContractAllowlist) == streamContractAllowlistSize` with both at 0 | 0 == 0; the one thing it still guarded (an entry quietly added to the map) now lives in `TestStreamContractRatchetIsClosed` |
| `TestStagingContractAllowlistShrinks` | `internal/modules/staging_contract_test.go` | flattened `stagingContractAllowlist` size == `stagingContractAllowlistSize` with both at 0 | same as above; map-empty check folded into `TestStagingContractRatchetIsClosed` |
| `TestCensusAccountingIdentity` | `internal/core/backend/argvector_coverage_test.go` | the pinned `census*` constants sum, `censusDriven == checked+notable`, `censusTimedOut == 0`, `len(noDispatchTasks) == censusNoDispatch` | arithmetic over constants only; `TestEveryRegisteredTaskIsAccountedFor` pins every bucket against the LIVE drive, including timedout=0 and the noDispatchTasks reasons |
| `TestUndrivableListIsPinned` | `internal/core/backend/argvector_drift_test.go` | `len(undrivableTasks) == 3` plus non-empty reasons | the len pin was a copy of the map; the reason check (and a registered-Task check) moved into `TestCensusBucketsCarryReasons` |
| `TestKnownBadArgVectorsArePinned` | `internal/core/backend/toolflags_test.go` | `len(knownBadArgVectors) == 0` and a loop over the empty map | 0 == 0 and a vacuous loop; `TestKnownBadArgVectorsAreStillBad` is the direction that bites |
| `TestBrutusDeadlineMatchesItsFormerBound` | `internal/core/backend/brutus_deadline_test.go` (file removed) | tools.lock `brutus.timeout_seconds == 1800`, the literal the module used to apply | TOML number vs a literal copied from it; the derivation lives in the tools.lock row |
| `TestJSADeadlineMatchesItsFormerBound` | `internal/core/backend/former_bounds_18_05_test.go` | tools.lock `JSA.timeout_seconds == 30` | same shape |
| `TestNomore403DeadlineMatchesItsFormerBound` | `internal/core/backend/former_bounds_18_05_test.go` | tools.lock `nomore403.timeout_seconds == 300` | same shape |
| `TestGitCloneDeadlineMatchesItsFormerBound` | `internal/core/backend/former_bounds_18_05_test.go` | tools.lock `git.timeout_seconds == 300` | same shape |
| `TestRoboxtractorDeadlineMatchesItsFormerBound` | `internal/core/backend/former_bounds_18_05_test.go` | tools.lock `roboxtractor.timeout_seconds == 120` | same shape |

Kept on purpose (they pin a real defect count or a property, not a copy):
`TestSilentSuccessAllowlistShrinks` (49, paired with `TestSilentSuccessAllowlistIsHonest`),
`TestInteractshHasNoManifestDeadline` (asserts a zero with the reason it must be zero),
`TestDerivedOutputExemptionsPinned` (asserts the one exemption by name), and the
`outputContractAllowlistSize` literal in `output_contract_test.go`, which 21-04
turned from `len(map)` into a typed number for exactly this reason.

Production comments that still name the deleted deadline pins (not edited here,
non-test files): `internal/modules/web/jsa.go:35`,
`internal/modules/web/wordlistgen.go:90`, `internal/modules/vulns/spray.go:41,92`.

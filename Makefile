# reconFTW v2 Makefile — Phase 3 plan-01 (Foundation Kernel)
#
# Primary targets (Go v2 kernel): build, test, test-integration, test-smoke, lint,
#   fmt, fmt-check, check, coverage, ci, clean.
# Sources: .planning/decisions/0002-architecture-v2.md §9, RESEARCH.md §"Stack Snapshot",
#   spike/go/Makefile (Phase 1 winner — port).
#
# v1 bash targets (bash-*, bootstrap, sync, upload, rm) live in Makefile.legacy,
# included below so they keep resolving while staying off this surface.
#
# `make ci` is the local mirror of .github/workflows/ci.yml — the same gates in
# the same order (see the `ci` target). When a step is added to one it is added
# to the other; the two drifting apart is how the repo got a gate that CI
# enforced on 5 files while the script enforced 13.
#
# XCUT-02 binary-size rationale: -ldflags="-s -w" strips symbols + DWARF debug info
# (per goreleaser convention); -trimpath removes the build host's filesystem paths
# from panic stacks and embedded build-id metadata (reproducibility + smaller binary).

.PHONY: help \
        build test test-integration test-smoke integration-smoke lint fmt fmt-check check \
        coverage coverage-core coverage-critical coverage-critical-selftest coverage-lib coverage-floor \
        govulncheck binary-size sentinel-gate ci clean \
        release-gates release-gates-selftest release-gates-ci release-gates-docker release-gates-provisioned

# Legacy bash targets (bash-*, bootstrap, sync, upload, rm). `-include` so a
# checkout without the file still builds; see `make help-legacy`.
-include Makefile.legacy

help:
	@echo "reconFTW v2 — Primary Go (kernel) targets"
	@echo ""
	@echo "  make build              - Strip + trimpath build to bin/reconftw (XCUT-02 <50MB gate)"
	@echo "  make test               - Ring 1 + Ring 4 (go test -race -short ./...)"
	@echo "  make test-integration   - Ring 1 + Ring 2 + Ring 4 (go test -race ./...)"
	@echo "  make test-smoke         - Ring 3 (go test -race -tags smoke ./...)"
	@echo "  make integration-smoke  - Hermetic E2E gate (fails if zero tests match)"
	@echo "  make lint               - golangci-lint run ./..."
	@echo "  make fmt                - gofumpt -w ."
	@echo "  make fmt-check          - gofumpt -d . (non-zero on any diff)"
	@echo "  make check              - fmt-check + lint + test (composite local gate)"
	@echo "  make coverage           - go test -coverprofile on internal/core/... (prints, does not gate)"
	@echo "  make coverage-core      - XCUT-04 ≥75% gate on internal/core/... (incl. resolvers; needs UDP/53)"
	@echo "  make coverage-critical  - XCUT-03 per-file ≥90% gate on critical paths"
	@echo "  make coverage-critical-selftest - Prove the critical gate can actually fail"
	@echo "  make coverage-lib       - XCUT-03 ≥75% lib-aggregate gate (resolvers-excluded)"
	@echo "  make coverage-floor     - ratchet floors for internal/modules + internal/store (scripts/coverage-floor.ratchet)"
	@echo "  make govulncheck        - reachability vuln scan (loud SKIP when govulncheck is not installed)"
	@echo "  make sentinel-gate      - XCUT-07 logging-hygiene sentinel, with a zero-match guard"
	@echo "  make binary-size        - XCUT-02 <50MB stripped-binary gate"
	@echo "  make ci                 - every ci.yml gate, in ci.yml order (see the target)"
	@echo "  make release-gates      - Phase 15: the 12 acceptance gates + the regression guard (lenient: SKIPPED is not fatal)"
	@echo "  make release-gates-selftest - Prove --require-all / --delegate can fail (stub go, ~2s)"
	@echo "  make release-gates-ci   - what ci.yml runs: --require-all, gates 11/13/14b DELEGATED with pointers"
	@echo "  make release-gates-docker - release-gates plus acceptance gate 11 (ARM64 docker run)"
	@echo "  make release-gates-provisioned - --require-all on a provisioned box (tool tree + RECONFTW_WORKSPACE); 11 delegated"
	@echo "  make clean              - rm -rf bin/ coverage.out"
	@echo ""
	@echo "  make help-legacy        - v1 bash targets (Makefile.legacy)"

# =============================================================================
# v2 Go targets (primary; Phase 3 Foundation Kernel)
# =============================================================================

# build: production-quality static binary; XCUT-02 budget <50MB.
#
# VERSION + BUILD_DATE per Plan 06 D-04 ldflag wiring — main.Version, main.CommitSHA,
# main.BuildDate are populated at link time so `reconftw version` prints real info.
# VERSION sourced from `git describe --tags --always --dirty`; BUILD_DATE is ISO-8601 UTC.
# Overridable at the make CLI: `make build VERSION=v2.0.0-rc1`.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT_SHA ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS := -s -w -X main.Version=$(VERSION) -X main.CommitSHA=$(COMMIT_SHA) -X main.BuildDate=$(BUILD_DATE)

build:
	go build -ldflags="$(LDFLAGS)" -trimpath -o bin/reconftw ./cmd/reconftw

# test: Ring 1 (unit) + Ring 4 (property-based). Fast (<90s budget per push).
test:
	go test -race -short ./...

# sentinel-gate: the XCUT-07 logging-hygiene sentinel as a NAMED step, so a
# rename or deletion is visible in CI as its own red row rather than as one
# fewer line in `go test ./...`.
#
# ci.yml used to run `-run 'TestXCUT07Sentinel|TestSentinel'`; `TestSentinel`
# never existed, and `go test -run` exits 0 on a pattern that matches nothing,
# so the step could only ever go red by the OTHER name failing. The -list
# count guard below is the same one integration-smoke uses: zero matches is a
# failure, not a pass.
SENTINEL_PATTERN ?= ^TestXCUT07Sentinel$$
SENTINEL_PKG ?= ./internal/core/log/

sentinel-gate:
	@matched=$$(go test -list '$(SENTINEL_PATTERN)' $(SENTINEL_PKG) 2>/dev/null | grep -c '^Test' || true); \
	echo "sentinel tests selected by $(SENTINEL_PATTERN) in $(SENTINEL_PKG): $$matched"; \
	if [ "$$matched" -eq 0 ]; then \
		echo "ERROR: the sentinel gate selected ZERO tests — a -run pattern matching nothing exits 0 and is a false green."; \
		exit 1; \
	fi
	go test -race -count=1 -run '$(SENTINEL_PATTERN)' $(SENTINEL_PKG)

# govulncheck: reachability-based scan, pinned in ci.yml. Locally the scanner
# may be absent; that is reported LOUDLY as a skip, never as a pass, and `make
# ci` prints the install line. CI always has it installed, so there it is a
# gate.
govulncheck:
	@if command -v govulncheck >/dev/null 2>&1; then \
		govulncheck ./...; \
	else \
		echo "SKIPPED govulncheck: not installed — this step was NOT executed."; \
		echo "        install the CI pin:  go install golang.org/x/vuln/cmd/govulncheck@v1.6.0"; \
	fi

# binary-size: XCUT-02. The same assertion ci.yml's binary-size job makes.
binary-size: build
	@size=$$(stat --printf=%s bin/reconftw 2>/dev/null || stat -f%z bin/reconftw); \
	echo "binary size: $$size bytes"; \
	if [ "$$size" -ge 52428800 ]; then \
		echo "ERROR: binary >=50MB (XCUT-02 gate)"; \
		exit 1; \
	fi

# realtools-args: run the real-tool ARG-VECTOR smoke test.
#
# internal/core/backend/smoke_test.go is gated behind //go:build realtools and,
# until this target existed, NOTHING ran it — not this Makefile, not CI, not
# release-gates. It read like arg-vector coverage while being dead code, and a
# wrong puredns flag (`-rt`, which pflag silently accepts as `-r` with value "t")
# shipped straight through it and broke every live recon run.
#
# NOT wired into `ci` on purpose: it needs the full 70-tool runtime on PATH, which
# CI runners do not have. Run it on a provisioned box before a release:
#
#	make realtools-args
#
# Tools absent from PATH are skipped, so a partial toolchain still reports on
# whatever it can reach.
# Runs the WHOLE realtools-tagged package, not one named test. The first version
# of this target used `-run TestRealToolArgVectors`, which silently excluded
# TestRealtoolsVulnsPhase6 and TestRealtoolsOSINTPhase7 in the same package — so
# it revived one third of the dead coverage and reported the result as if it were
# all of it. That is the same shape as the dead build tag it was written to fix.
#
# THE COUNT ASSERTION MUST NAME THE TESTS, NOT COUNT LINES. The previous version
# counted `^=== RUN   Test` and required >= 3. That was a false green twice over:
# `-tags realtools` builds the WHOLE package, so the ~42 untagged tests in it
# already satisfy >= 3 on their own, and the pattern also matches subtest RUN
# lines. Deleting both realtools files outright would have left this target
# green. It now greps for each of the three test functions BY NAME and fails
# naming the missing one — which is the only form of the assertion that a rename
# or a re-tag cannot slip past.
#
# NOT wired into `ci`: it needs the 70-tool runtime on PATH, which CI runners do
# not have. On a partial toolchain each probe reports CENSUS_ONLY and prints what
# it did not verify. Set REALTOOLS_REFERENCE=1 on a provisioned box to enforce
# the known-absent ratchet — see internal/core/backend/realtools_census_test.go.
#
# 17-04 adds a FOURTH realtools test and a FIFTH, HERMETIC one:
#
#   TestRealtoolsFixedArgVectors        runs each of the six fixed arg vectors
#                                       against its installed binary and asserts
#                                       the tool ACCEPTS the invocation.
#   TestEveryRegisteredTaskIsAccountedFor
#                                       the hermetic completeness census over all
#                                       97 registered Tasks. It needs no binaries,
#                                       but it belongs in the same output surface
#                                       so ONE target reports BOTH the hermetic
#                                       coverage and the real-tool coverage.
#
# The two are guarded separately because they emit DIFFERENT census lines, and a
# guard that counted them together would be satisfied by four of one and none of
# the other — the same shape as the `>= 3` count this target already replaced.
REALTOOLS_TESTS := TestRealToolArgVectors TestRealtoolsVulnsPhase6 TestRealtoolsOSINTPhase7 TestRealtoolsFixedArgVectors

# COVERAGE_TESTS emit ARGV_COVERAGE rather than REALTOOLS_CENSUS. Required BY
# NAME and by census line, for the same reason as above.
COVERAGE_TESTS := TestEveryRegisteredTaskIsAccountedFor

# JSONL_TESTS emit TOOLS_JSONL_COVERAGE — the fourth census (18-06), which
# answers "does this tool appear in logs/tools.jsonl at all". A THIRD list rather
# than an addition to either of the two above, because each list is guarded by
# the census line its members emit and mixing them makes the guard satisfiable by
# the wrong members. That is the same defect this target's own history records
# twice already (the `>= 3` line count, and the one-third `-run` selector).
JSONL_TESTS := TestToolsJsonlCoverage

# PRESENCE_TESTS must RUN but emit no census line of their own.
#
# 18-02 added TestRegulatorDispatchesThroughTheRunner (//go:build realtools) and
# it was never ratcheted here — an omission 18-06 found and is closing. It could
# not simply be appended to REALTOOLS_TESTS: that list is cross-checked against
# the COUNT of REALTOOLS_CENSUS lines, so a fifth name with no census line would
# have made the target fail for a reason unrelated to coverage.
#
# WHAT THIS LIST DOES AND DOES NOT ASSERT, stated because the difference is the
# whole value. `=== RUN` is printed for a SKIPPED test too, and this one skips
# cleanly when the regulator clone is absent. So membership here asserts the test
# still EXISTS, is still selected, and still compiles under the realtools tag —
# it catches a rename, a deletion or a re-tag. It does NOT assert the regulator
# leg was verified on this box. Anyone reading a green run must not infer that it
# was; the REALTOOLS_RESOLVED line in the log is what says so.
PRESENCE_TESTS := TestRegulatorDispatchesThroughTheRunner

realtools-args:
	@out=$$(go test -tags realtools -count=1 -v ./internal/core/backend/ 2>&1); \
	echo "$$out"; \
	missing=""; \
	for tn in $(REALTOOLS_TESTS) $(COVERAGE_TESTS) $(JSONL_TESTS) $(PRESENCE_TESTS); do \
		echo "$$out" | grep -qE "^=== RUN   $$tn$$" || missing="$$missing $$tn"; \
	done; \
	if [ -n "$$missing" ]; then \
		echo "ERROR: these realtools test(s) did NOT run:$$missing"; \
		echo "       A renamed, deleted or re-tagged test makes this target report on coverage"; \
		echo "       that no longer exists. Fix the test or update REALTOOLS_TESTS — deliberately."; \
		exit 1; \
	fi; \
	census=$$(echo "$$out" | grep -c 'REALTOOLS_CENSUS test=' || true); \
	if [ "$$census" -ne $(words $(REALTOOLS_TESTS)) ]; then \
		echo "ERROR: $$census REALTOOLS_CENSUS line(s), expected $(words $(REALTOOLS_TESTS)) (one per test)."; \
		echo "       Every probe must report what it did NOT verify. A run whose skip count is unknown"; \
		echo "       reads as coverage and is not."; \
		exit 1; \
	fi; \
	for tn in $(COVERAGE_TESTS); do \
		echo "$$out" | grep -qE 'ARGV_COVERAGE registered=[0-9]+ driven=' || { \
			echo "ERROR: $$tn ran but emitted NO 'ARGV_COVERAGE registered=' line."; \
			echo "       The hermetic completeness census is the only thing that reports the Tasks"; \
			echo "       NOBODY is checking. A run without it is a run whose coverage is unknown."; \
			exit 1; \
		}; \
	done; \
	for tn in $(JSONL_TESTS); do \
		echo "$$out" | grep -qE 'TOOLS_JSONL_COVERAGE tools=[^ ]' || { \
			echo "ERROR: $$tn ran but emitted NO 'TOOLS_JSONL_COVERAGE tools=' line, or an empty one."; \
			echo "       That census names the tools this phase brought onto the seam. An empty list"; \
			echo "       reads as a clean smaller set and is the shape it exists to refuse."; \
			exit 1; \
		}; \
	done; \
	echo "$$out" | grep 'REALTOOLS_CENSUS test='; \
	echo "$$out" | grep 'ARGV_COVERAGE registered='; \
	echo "$$out" | grep 'TOOLS_JSONL_COVERAGE tools='; \
	echo "realtools: all $(words $(REALTOOLS_TESTS)) real-tool + $(words $(COVERAGE_TESTS)) coverage + $(words $(JSONL_TESTS)) jsonl + $(words $(PRESENCE_TESTS)) presence test(s) executed"; \
	echo "$$out" | grep -qE '^(FAIL|--- FAIL|    --- FAIL)' && exit 1 || exit 0

# test-integration: Ring 1 + Ring 2 + Ring 4. Per-commit (<5min budget).
test-integration:
	go test -race ./...

# test-smoke: Ring 3 (smoke; build-tagged). Weekly cron + every PR, and the
# per-platform job. Runs ONLY the tests that exist under `-tags smoke`, in the
# packages that declare them, and COMPUTES that set: names listed under the tag
# minus names listed without it. Counting `go test -tags smoke -list . ./...`
# would count every untagged test too and could never reach zero, and a
# hardcoded name list rots the first time a smoke test is renamed — both are
# the `-run` false green this repo keeps re-finding. Zero smoke-only tests is a
# failure.
#
# Package discovery goes through `go list`, not `grep -r`: go list ignores
# directories starting with `.` or `_` and testdata/, so a stray worktree under
# .claude/ or a vendored copy cannot be picked up as a package (grep -rl did
# exactly that on the first run of this target).
test-smoke:
	@set -e; \
	tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT; \
	go list -tags smoke -f '{{.ImportPath}} {{.TestGoFiles}} {{.XTestGoFiles}}' ./... | sort > "$$tmp/pkgs-tagged"; \
	go list -f '{{.ImportPath}} {{.TestGoFiles}} {{.XTestGoFiles}}' ./... | sort > "$$tmp/pkgs-untagged"; \
	pkgs=$$(comm -13 "$$tmp/pkgs-untagged" "$$tmp/pkgs-tagged" | awk '{print $$1}'); \
	if [ -z "$$pkgs" ]; then echo "ERROR: no package gains a test file under -tags smoke — the smoke ring is empty"; exit 1; fi; \
	echo "packages with smoke-tagged tests:"; echo "$$pkgs"; \
	go test -tags smoke -list . $$pkgs | grep '^Test' | sort -u > "$$tmp/tagged"; \
	go test -list . $$pkgs | grep '^Test' | sort -u > "$$tmp/untagged"; \
	comm -13 "$$tmp/untagged" "$$tmp/tagged" > "$$tmp/smoke"; \
	count=$$(grep -c '^Test' "$$tmp/smoke" || true); \
	echo "smoke-only tests: $$count"; cat "$$tmp/smoke"; \
	if [ "$$count" -eq 0 ]; then echo "ERROR: ZERO smoke-only tests computed — refusing to report success."; exit 1; fi; \
	pattern="^($$(paste -sd'|' - < "$$tmp/smoke"))$$"; \
	echo "running: go test -race -count=1 -tags smoke -run '$$pattern'"; \
	go test -race -count=1 -tags smoke -run "$$pattern" -v $$pkgs

# integration-smoke: hermetic end-to-end gate.
# Drives production record types through the real staging write, merge and
# scope gate, asserting artefact CONTENT rather than exit codes.
#
# The match-count guard is load-bearing: `go test -run` exits 0 when its
# pattern matches nothing, which is how the deleted TestKernelDemoEndToEnd
# kept this target (and CI) green while running no tests at all.
E2E_PATTERN ?= ^TestE2E

integration-smoke:
	@matched=$$(go test -list '$(E2E_PATTERN)' ./... 2>/dev/null | grep -c '^TestE2E' || true); \
	echo "E2E tests selected by $(E2E_PATTERN): $$matched"; \
	if [ "$$matched" -eq 0 ]; then \
		echo "ERROR: E2E gate selected ZERO tests — refusing to report success."; \
		exit 1; \
	fi
	go test -race -run '$(E2E_PATTERN)' ./...

lint:
	golangci-lint run ./...

fmt:
	gofumpt -w .

fmt-check:
	gofumpt -d . | (! grep .)

# check: composite local-gate matching CI's lint+test sequence.
# Plan 07: includes integration-smoke (Phase 3 acceptance integration test).
check: fmt-check lint test integration-smoke

# coverage: Phase 3 XCUT-04 profile on internal/core/... — prints the total,
# does not gate. Includes internal/core/resolvers, whose tests need outbound
# UDP/53 and hang offline; use coverage-lib for the offline figure.
coverage:
	go test -race -coverprofile=coverage.out -covermode=atomic ./internal/core/...
	go tool cover -func=coverage.out | tail -1

# coverage-core: the XCUT-04 ≥75% gate exactly as ci.yml's integration job
# asserts it (same package set, same threshold). Needs UDP/53 for the same
# reason as `coverage`; `make ci` runs it because CI does.
COVERAGE_CORE_GATE ?= 75.0

coverage-core:
	go test -race -coverprofile=coverage.out -covermode=atomic ./internal/core/...
	@go tool cover -func=coverage.out | tail -1 | awk -v gate='$(COVERAGE_CORE_GATE)' '{ \
		pct = substr($$3, 1, length($$3) - 1) + 0; \
		if (pct < gate + 0) { print "Coverage below " gate "% gate:", $$3; exit 1 } \
		else { print "Coverage:", $$3 } }'

# coverage-critical: XCUT-03 per-file ≥90% gate on the kernel critical paths.
# Files seeded across Plan 03 plans 01-05; see scripts/coverage-critical.sh.
#
# The script is the SINGLE SOURCE OF TRUTH for the file list, the package list
# and the threshold — .github/workflows/ci.yml calls this target rather than
# carrying its own copy (the two copies had already drifted: CI enforced 5 files,
# the script 13). GATE, REFRESH_COVERAGE and CRITICAL_COVERAGE_PROFILE reach the
# script through the recipe's environment, so both `GATE=95 make coverage-critical`
# and `make coverage-critical GATE=95` override the default.
#
# Invoked through `bash` rather than as `./scripts/...`: this repo sets
# core.fileMode=false, so every script under scripts/ was recorded in the tree as
# 100644 and a fresh `actions/checkout` materialises it without the execute bit
# (verified: `./scripts/coverage-critical.sh` exits 126 from a clean export).
# The mode is now 100755 as well, but the explicit interpreter is what keeps
# these targets working regardless of how the tree is unpacked.
coverage-critical:
	@bash ./scripts/coverage-critical.sh

# coverage-critical-selftest: proves the gate above is CAPABLE of failing.
# It feeds coverage-critical.sh synthetic coverprofiles and asserts a non-zero
# exit on (a) a file whose statement-weighted coverage is below the gate but
# whose per-function average is above it, and (b) a listed file with no measured
# statements. Both inputs PASSED the pre-15-07 implementation. Cheap (no
# `go test`), so it runs in CI immediately before the gate itself.
coverage-critical-selftest:
	@bash ./scripts/coverage_critical_test.sh

# coverage-lib: XCUT-03 ≥75% lib-aggregate gate. Excludes internal/core/resolvers
# (UDP/53 hang offline) — the full lib-wide figure incl. resolvers is a tracked
# risk measured on a network host. See scripts/coverage-lib.sh. ~11s offline,
# which is why ci.yml's integration job runs it too.
coverage-lib:
	@bash ./scripts/coverage-lib.sh

# coverage-floor: ratchet floors for internal/modules/... and internal/store/...
# — the two trees no other coverage gate looks at. Floors live in
# scripts/coverage-floor.ratchet; the script holds no number. ~12s offline.
coverage-floor:
	@bash ./scripts/coverage-floor.sh

# ci: the .github/workflows/ci.yml pipeline, job by job, in the same order.
#
#   lint job          fmt-check lint
#   govulncheck job   govulncheck            (loud SKIP if not installed locally)
#   unit job          test sentinel-gate
#   integration job   test-integration coverage-core coverage-critical-selftest
#                     coverage-critical coverage-lib coverage-floor
#   integration-smoke integration-smoke + the interfaces_check build
#   binary-size job   binary-size
#   release-gates job release-gates-selftest release-gates-ci  (--require-all; 11/13/14b DELEGATED)
#
# The smoke and platform-smoke jobs are `make test-smoke`; they are not in `ci`
# because CI runs them per-PR / per-platform rather than per push. Running
# `make ci` is the pre-push answer to "will CI be green".
#
# coverage-critical-selftest runs immediately before coverage-critical, in the
# same order as ci.yml: verify the gate can still fail, then let it judge. The
# self-tests are deliberately NOT in `make test` or `make check` — those are
# the per-push loop, and a self-test only guards edits to its gate.
ci: fmt-check lint govulncheck test sentinel-gate test-integration coverage-core coverage-critical-selftest coverage-critical coverage-lib coverage-floor integration-smoke interfaces-check binary-size release-gates-selftest release-gates-ci

.PHONY: interfaces-check
interfaces-check:
	go build ./cmd/interfaces_check/...

# release-gates: phase 15's cutover sign-off gate.
#
# Runs the eight regression-guard commands from 15-CONTEXT.md, BOTH CI-break
# classes `go test ./...` cannot catch (a clean-PATH health-check and
# per-package critical coverage), and one named `go test -run` invocation per
# TEST-OWNED row of the thirteen-row gate table, each asserting that tests
# actually ran.
#
# Acceptance gate 11 (ARM64 `docker run`) is OFF by default so this target works
# on a machine without Docker/QEMU; it is reported SKIPPED with its reason
# rather than omitted. `release-gates-docker` turns it on.
#
# Invoked through `bash` for the same reason as coverage-critical: this repo sets
# core.fileMode=false, so a fresh `actions/checkout` can materialise scripts/
# without the execute bit.
release-gates:
	@bash ./scripts/release-gates.sh

# release-gates-selftest: proves --require-all and --delegate can FAIL. Drives
# the real script with a stub `go` and no tool tree (the shape of a CI runner)
# and asserts exit codes and summary wording. Runs in ci.yml immediately before
# the gates themselves, same posture as coverage-critical-selftest.
release-gates-selftest:
	@bash ./scripts/release_gates_test.sh

# release-gates-ci: EXACTLY what ci.yml's release-gates job runs. Every gate is
# PASS, FAIL or DELEGATED-with-a-pointer; a SKIPPED gate fails the run. The
# three delegations are the three gates a CI runner cannot execute:
#   11  ARM64 docker run     -> docker_nightly.yml `Verify image health (linux/arm64)`
#   13  real-tool arg vectors -> make release-gates-provisioned (operator, tool tree)
#   14b real nuclei coverage  -> make release-gates-provisioned (operator, RECONFTW_WORKSPACE)
# RELEASE_GATES_LOGDIR, when set, is a caller-owned directory the script never
# removes; ci.yml uploads summary.txt and gate13_argvector.log from it.
release-gates-ci:
	@bash ./scripts/release-gates.sh --require-all --delegate 11 --delegate 13 --delegate 14b \
		$${RELEASE_GATES_LOGDIR:+--logdir "$$RELEASE_GATES_LOGDIR"}

release-gates-docker:
	@bash ./scripts/release-gates.sh --with-docker

# release-gates-provisioned: the operator's half of the sign-off, on a box with
# the 70-tool runtime and, for gate 14b, RECONFTW_WORKSPACE exported to a real
# run's workspace. --require-all with ONLY gate 11 delegated: 13 and 14b must
# execute here or the run fails. This is the named target the DELEGATED rows in
# CI point at.
release-gates-provisioned:
	@bash ./scripts/release-gates.sh --require-all --delegate 11 \
		$${RELEASE_GATES_LOGDIR:+--logdir "$$RELEASE_GATES_LOGDIR"}

clean:
	rm -rf bin/ coverage.out coverage-lib.out

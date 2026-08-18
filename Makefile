# reconFTW v2 Makefile — Phase 3 plan-01 (Foundation Kernel)
#
# Primary targets (Go v2 kernel): build, test, test-integration, test-smoke, lint,
#   fmt, fmt-check, check, coverage, ci, clean.
# Sources: .planning/decisions/0002-architecture-v2.md §9, RESEARCH.md §"Stack Snapshot",
#   spike/go/Makefile (Phase 1 winner — port).
#
# v1 bash targets (transitional, preserved until Phase 12 cutover): bash-lint,
#   bash-fmt, bash-test, bash-test-unit, bash-test-integration-smoke,
#   bash-test-integration-full, bash-test-security, bash-test-all,
#   bash-test-release-gate, bash-setup-dev, sync, upload, bootstrap, rm.
#
# XCUT-02 binary-size rationale: -ldflags="-s -w" strips symbols + DWARF debug info
# (per goreleaser convention); -trimpath removes the build host's filesystem paths
# from panic stacks and embedded build-id metadata (reproducibility + smaller binary).

GH_CLI := $(shell command -v gh 2> /dev/null)
# PRIV_REPO is read from the environment by each recipe below (not interpolated
# via $(shell ...) so that shell metacharacters stay as data rather than syntax).
# Default: reconftw-data.

.PHONY: help \
        build test test-integration test-smoke integration-smoke lint fmt fmt-check check coverage coverage-critical coverage-critical-selftest coverage-lib ci clean \
        release-gates release-gates-docker \
        sync upload bootstrap rm \
        bash-lint bash-lint-fix bash-fmt bash-test bash-test-unit bash-test-integration-smoke \
        bash-test-integration-full bash-test-security bash-test-all bash-test-release-gate \
        bash-setup-dev

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
	@echo "  make coverage           - go test -coverprofile on internal/core/..."
	@echo "  make coverage-critical  - XCUT-03 per-file ≥90% gate on critical paths"
	@echo "  make coverage-critical-selftest - Prove the critical gate can actually fail"
	@echo "  make coverage-lib       - XCUT-03 ≥75% lib-aggregate gate (resolvers-excluded)"
	@echo "  make ci                 - fmt-check + lint + test + gate self-test + both coverage gates (matches CI)"
	@echo "  make release-gates      - Phase 15: the 12 acceptance gates + the regression guard"
	@echo "  make release-gates-docker - release-gates plus acceptance gate 11 (ARM64 docker run)"
	@echo "  make clean              - rm -rf bin/ coverage.out"
	@echo ""
	@echo "reconFTW v1 — Transitional bash targets (until Phase 12 cutover)"
	@echo ""
	@echo "  make bash-test          - bats unit tests"
	@echo "  make bash-test-unit     - bats unit tests"
	@echo "  make bash-test-integration-smoke - bats smoke tests"
	@echo "  make bash-test-integration-full  - bats full integration tests"
	@echo "  make bash-test-release-gate - bats release-quality gate"
	@echo "  make bash-test-all      - bats unit + integration"
	@echo "  make bash-test-security - bats security tests"
	@echo "  make bash-lint          - shellcheck (error level)"
	@echo "  make bash-lint-fix      - shellcheck (warning, gcc-format)"
	@echo "  make bash-fmt           - shfmt -bn -ci -i 4"
	@echo "  make bash-setup-dev     - pre-commit install"
	@echo ""
	@echo "  make bootstrap          - Create private data repo"
	@echo "  make sync               - Sync with upstream"
	@echo "  make upload             - Upload data to private repo"

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

# test-integration: Ring 1 + Ring 2 + Ring 4. Per-commit (<5min budget).
test-integration:
	go test -race ./...

# test-smoke: Ring 3 (smoke; build-tagged). Weekly cron + every PR.
test-smoke:
	go test -race -tags smoke ./...

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

# coverage: Phase 3 XCUT-04 gate (≥75% on lib code; ≥90% on critical paths per XCUT-03).
coverage:
	go test -race -coverprofile=coverage.out -covermode=atomic ./internal/core/...
	go tool cover -func=coverage.out | tail -1

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
# risk measured on a network host. See scripts/coverage-lib.sh.
coverage-lib:
	@bash ./scripts/coverage-lib.sh

# ci: composite gate matching the .github/workflows/ci.yml pipeline.
# Both XCUT-03 coverage gates run here (they replace the bare, non-gating
# `coverage` target, which additionally hangs on resolvers offline). Both gates
# are resolvers-excluded and therefore runnable offline.
#
# coverage-critical-selftest runs immediately before coverage-critical, in the
# same order as ci.yml: verify the gate can still fail, then let it judge. It is
# deliberately NOT in `make test` or `make check` — those are the per-push loop,
# and the self-test only guards edits to the gate itself.
ci: fmt-check lint test coverage-critical-selftest coverage-critical coverage-lib

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

release-gates-docker:
	@bash ./scripts/release-gates.sh --with-docker

clean:
	rm -rf bin/ coverage.out coverage-lib.out

# =============================================================================
# v1 bash targets (transitional; preserved until Phase 12 cutover)
# =============================================================================

# bootstrap a private repo to store data
#
# All repo/branch values are validated and quoted inside each recipe so shell
# metacharacters in PRIV_REPO env or in the remote's HEAD ref name cannot be
# interpreted by /bin/sh (cmd injection mitigation).
bootstrap:
	@if [ -z "$(GH_CLI)" ]; then echo "github cli is missing. please install"; exit 2; fi
	@repo="$${PRIV_REPO:-reconftw-data}"; \
	case "$$repo" in (*[!A-Za-z0-9._/-]*|'') echo "invalid repo name: $$repo"; exit 2;; esac; \
	gh repo create "$$repo" --private && \
	gh repo clone "$$repo" "$$HOME/$$repo" && \
	cd "$$HOME/$$repo" && \
	branch=$$(git symbolic-ref --short refs/remotes/origin/HEAD | sed 's@^origin/@@') && \
	git check-ref-format --branch "$$branch" >/dev/null || { echo "invalid default branch: $$branch"; exit 1; } && \
	git commit --allow-empty -m "Empty commit" && \
	git remote add upstream https://github.com/six2dez/reconftw && \
	git fetch upstream && \
	git rebase upstream/main "$$branch" && \
	mkdir Recon && \
	git push origin "$$branch" && \
	echo "Done!" && \
	echo "Initialized private repo: $$repo"
	@echo "bootstrap complete"

rm:
	@repo="$${PRIV_REPO:-reconftw-data}"; \
	case "$$repo" in (*[!A-Za-z0-9._/-]*|'') echo "invalid repo name: $$repo"; exit 2;; esac; \
	gh repo delete "$$repo" --yes && \
	rm -rf -- "$$HOME/$$repo"

sync:
	@repo="$${PRIV_REPO:-reconftw-data}"; \
	case "$$repo" in (*[!A-Za-z0-9._/-]*|'') echo "invalid repo name: $$repo"; exit 2;; esac; \
	cd "$$HOME/$$repo" && \
	git fetch upstream && \
	branch=$$(git symbolic-ref --short refs/remotes/origin/HEAD | sed 's@^origin/@@') && \
	git check-ref-format --branch "$$branch" >/dev/null || { echo "invalid default branch: $$branch"; exit 1; } && \
	git rebase upstream/main "$$branch"

upload:
	@repo="$${PRIV_REPO:-reconftw-data}"; \
	case "$$repo" in (*[!A-Za-z0-9._/-]*|'') echo "invalid repo name: $$repo"; exit 2;; esac; \
	cd "$$HOME/$$repo" && \
	git add . && \
	git commit -m "Data upload" && \
	branch=$$(git symbolic-ref --short refs/remotes/origin/HEAD | sed 's@^origin/@@') && \
	git check-ref-format --branch "$$branch" >/dev/null || { echo "invalid default branch: $$branch"; exit 1; } && \
	git push origin "$$branch"

bash-lint:
	@if command -v shellcheck >/dev/null 2>&1; then \
		shellcheck -S error reconftw.sh modules/*.sh lib/*.sh install.sh; \
	else \
		echo "shellcheck not found. Install: https://www.shellcheck.net/"; \
		exit 1; \
	fi

bash-lint-fix:
	@if command -v shellcheck >/dev/null 2>&1; then \
		shellcheck -S warning -f gcc reconftw.sh modules/*.sh lib/*.sh install.sh; \
	else \
		echo "shellcheck not found. Install: https://www.shellcheck.net/"; \
		exit 1; \
	fi

bash-fmt:
	@if command -v shfmt >/dev/null 2>&1; then \
		shfmt -w -i 4 -bn -ci install.sh reconftw.sh modules/*.sh lib/*.sh; \
	else \
		echo "shfmt not found. Install: https://github.com/mvdan/sh"; \
		exit 1; \
	fi

bash-test:
	@if command -v bats >/dev/null 2>&1; then \
		./tests/run_tests.sh --unit; \
	else \
		echo "bats-core not found. Install: https://github.com/bats-core/bats-core"; \
		exit 1; \
	fi

bash-test-unit:
	@if command -v bats >/dev/null 2>&1; then \
		./tests/run_tests.sh --unit; \
	else \
		echo "bats-core not found. Install: https://github.com/bats-core/bats-core"; \
		exit 1; \
	fi

bash-test-integration-smoke:
	@if command -v bats >/dev/null 2>&1; then \
		./tests/run_tests.sh --smoke; \
	else \
		echo "bats-core not found. Install: https://github.com/bats-core/bats-core"; \
		exit 1; \
	fi

bash-test-integration-full:
	@if command -v bats >/dev/null 2>&1; then \
		./tests/run_tests.sh --integration; \
	else \
		echo "bats-core not found. Install: https://github.com/bats-core/bats-core"; \
		exit 1; \
	fi

bash-test-security:
	@if command -v bats >/dev/null 2>&1; then \
		bats tests/security/*.bats; \
	else \
		echo "bats-core not found. Install: https://github.com/bats-core/bats-core"; \
		exit 1; \
	fi

bash-test-all:
	@if command -v bats >/dev/null 2>&1; then \
		./tests/run_tests.sh --all; \
	else \
		echo "bats-core not found. Install: https://github.com/bats-core/bats-core"; \
		exit 1; \
	fi

bash-test-release-gate:
	@bash -n reconftw.sh modules/*.sh lib/*.sh
	@./tests/run_tests.sh --unit
	@./tests/run_tests.sh --smoke
	@if [ -f Recon/*/.log/perf_summary.json ]; then \
		latest=$$(ls -1t Recon/*/.log/perf_summary.json | head -n1); \
		tests/bench/compare_baseline.sh tests/bench/baseline_metrics.json "$$latest"; \
	else \
		echo "[INFO] No perf summary found under Recon/*/.log; skipping perf regression gate"; \
	fi

bash-setup-dev:
	@if command -v pre-commit >/dev/null 2>&1; then \
		pre-commit install; \
		echo "Pre-commit hooks installed!"; \
	else \
		echo "pre-commit not found. Install: pip install pre-commit"; \
		exit 1; \
	fi

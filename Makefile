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
        build test test-integration test-smoke lint fmt fmt-check check coverage ci clean \
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
	@echo "  make lint               - golangci-lint run ./..."
	@echo "  make fmt                - gofumpt -w ."
	@echo "  make fmt-check          - gofumpt -d . (non-zero on any diff)"
	@echo "  make check              - fmt-check + lint + test (composite local gate)"
	@echo "  make coverage           - go test -coverprofile on internal/core/..."
	@echo "  make ci                 - fmt-check + lint + test + coverage (matches CI)"
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
# This target fails until Plan 03-05 lands cmd/reconftw/main.go — intentional fail-fast
# so CI surfaces the binary-size gate the moment the first main.go commits.
build:
	go build -ldflags="-s -w" -trimpath -o bin/reconftw ./cmd/reconftw

# test: Ring 1 (unit) + Ring 4 (property-based). Fast (<90s budget per push).
test:
	go test -race -short ./...

# test-integration: Ring 1 + Ring 2 + Ring 4. Per-commit (<5min budget).
test-integration:
	go test -race ./...

# test-smoke: Ring 3 (smoke; build-tagged). Weekly cron + every PR.
test-smoke:
	go test -race -tags smoke ./...

lint:
	golangci-lint run ./...

fmt:
	gofumpt -w .

fmt-check:
	gofumpt -d . | (! grep .)

# check: composite local-gate matching CI's lint+test sequence.
check: fmt-check lint test

# coverage: Phase 3 XCUT-04 gate (≥75% on lib code; ≥90% on critical paths per XCUT-03).
coverage:
	go test -race -coverprofile=coverage.out -covermode=atomic ./internal/core/...
	go tool cover -func=coverage.out | tail -1

# ci: composite gate matching the .github/workflows/ci.yml pipeline.
ci: fmt-check lint test coverage

clean:
	rm -rf bin/ coverage.out

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

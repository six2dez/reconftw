GH_CLI := $(shell command -v gh 2> /dev/null)
# PRIV_REPO is read from the environment by each recipe below (not interpolated
# via $(shell ...) so that shell metacharacters stay as data rather than syntax).
# Default: reconftw-data.

.PHONY: sync upload bootstrap rm lint lint-fix fmt test test-all test-security test-unit test-integration-smoke test-integration-full test-release-gate setup-dev help

help:
	@echo "reconFTW Development Commands"
	@echo ""
	@echo "  make test          - Run unit tests"
	@echo "  make test-unit     - Run unit tests"
	@echo "  make test-integration-smoke - Run integration smoke tests"
	@echo "  make test-integration-full  - Run full integration tests"
	@echo "  make test-release-gate - Run release quality gate checks"
	@echo "  make test-all      - Run all tests (unit + integration)"
	@echo "  make test-security - Run security tests"
	@echo "  make lint          - Check code with shellcheck"
	@echo "  make lint-fix      - Show shellcheck issues with context"
	@echo "  make fmt           - Format code with shfmt"
	@echo "  make setup-dev     - Install pre-commit hooks"
	@echo ""
	@echo "  make bootstrap     - Create private data repo"
	@echo "  make sync          - Sync with upstream"
	@echo "  make upload        - Upload data to private repo"

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

lint:
	@if command -v shellcheck >/dev/null 2>&1; then \
		shellcheck -S error reconftw.sh modules/*.sh lib/*.sh install.sh; \
	else \
		echo "shellcheck not found. Install: https://www.shellcheck.net/"; \
		exit 1; \
	fi

lint-fix:
	@if command -v shellcheck >/dev/null 2>&1; then \
		shellcheck -S warning -f gcc reconftw.sh modules/*.sh lib/*.sh install.sh; \
	else \
		echo "shellcheck not found. Install: https://www.shellcheck.net/"; \
		exit 1; \
	fi

fmt:
	@if command -v shfmt >/dev/null 2>&1; then \
		shfmt -w -i 4 -bn -ci install.sh reconftw.sh modules/*.sh lib/*.sh; \
	else \
		echo "shfmt not found. Install: https://github.com/mvdan/sh"; \
		exit 1; \
	fi

test:
	@if command -v bats >/dev/null 2>&1; then \
		./tests/run_tests.sh --unit; \
	else \
		echo "bats-core not found. Install: https://github.com/bats-core/bats-core"; \
		exit 1; \
	fi

test-unit:
	@if command -v bats >/dev/null 2>&1; then \
		./tests/run_tests.sh --unit; \
	else \
		echo "bats-core not found. Install: https://github.com/bats-core/bats-core"; \
		exit 1; \
	fi

test-integration-smoke:
	@if command -v bats >/dev/null 2>&1; then \
		./tests/run_tests.sh --smoke; \
	else \
		echo "bats-core not found. Install: https://github.com/bats-core/bats-core"; \
		exit 1; \
	fi

test-integration-full:
	@if command -v bats >/dev/null 2>&1; then \
		./tests/run_tests.sh --integration; \
	else \
		echo "bats-core not found. Install: https://github.com/bats-core/bats-core"; \
		exit 1; \
	fi

test-security:
	@if command -v bats >/dev/null 2>&1; then \
		bats tests/security/*.bats; \
	else \
		echo "bats-core not found. Install: https://github.com/bats-core/bats-core"; \
		exit 1; \
	fi

test-all:
	@if command -v bats >/dev/null 2>&1; then \
		./tests/run_tests.sh --all; \
	else \
		echo "bats-core not found. Install: https://github.com/bats-core/bats-core"; \
		exit 1; \
	fi

test-release-gate:
	@bash -n reconftw.sh modules/*.sh lib/*.sh
	@./tests/run_tests.sh --unit
	@./tests/run_tests.sh --smoke
	@if [ -f Recon/*/.log/perf_summary.json ]; then \
		latest=$$(ls -1t Recon/*/.log/perf_summary.json | head -n1); \
		tests/bench/compare_baseline.sh tests/bench/baseline_metrics.json "$$latest"; \
	else \
		echo "[INFO] No perf summary found under Recon/*/.log; skipping perf regression gate"; \
	fi

setup-dev:
	@if command -v pre-commit >/dev/null 2>&1; then \
		pre-commit install; \
		echo "Pre-commit hooks installed!"; \
	else \
		echo "pre-commit not found. Install: pip install pre-commit"; \
		exit 1; \
	fi

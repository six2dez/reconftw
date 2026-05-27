# Spike PoC — DO NOT EVOLVE INTO PRODUCTION
# Source: .planning/phases/01-language-adr-spike/01-03-PLAN.md Task 1
# Symmetric with spike/go/Makefile

.PHONY: build test integration-test lint clean loc session-start session-end

build:
	uv pip install -e .
	uv run pyinstaller --onefile --name spike src/spike/__main__.py --distpath dist --workpath build --specpath build

test:
	uv run pytest tests/ -v -m "not integration"

integration-test:
	uv run pytest tests/ -v -m integration

lint:
	uv run ruff check src/ tests/ 2>/dev/null || true

clean:
	rm -rf dist/ build/ *.egg-info src/spike.egg-info .pytest_cache out/

loc:
	command -v tokei >/dev/null && tokei src/spike --output json || (command -v cloc >/dev/null && cloc src/spike --json) || echo "tokei or cloc required"

session-start:
	date +%s > .spike_session_start && echo "Session started at $$(date)"

session-end:
	[[ -f .spike_session_start ]] && echo "python $$(( ( $$(date +%s) - $$(cat .spike_session_start) ) / 60 ))" >> ../.spike_sessions.log && rm .spike_session_start && echo "Session logged"

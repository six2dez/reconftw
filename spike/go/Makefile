# spike/go/Makefile — Go spike build system
# Spike PoC — DO NOT EVOLVE INTO PRODUCTION
# Source: .planning/phases/01-language-adr-spike/01-02-PLAN.md Task 1
# Symmetric with: spike/python/Makefile (Plan 01-03)

.PHONY: build test integration-test lint clean loc session-start session-end

build:
	go build -ldflags="-s -w" -trimpath -o bin/spike ./cmd/spike

test:
	go test ./tests/... -v -timeout 60s

integration-test:
	go test ./tests/... -v -tags=integration -timeout 300s

lint:
	go vet ./... && (command -v golangci-lint && golangci-lint run || echo "golangci-lint not installed, skipping")

clean:
	rm -rf bin/ out/

loc:
	(command -v tokei && tokei . --output json) || (command -v cloc && cloc .) || echo "tokei or cloc required"

session-start:
	date +%s > .spike_session_start && echo "Session started at $$(date)"

session-end:
	[[ -f .spike_session_start ]] && echo "go $$(( ( $$(date +%s) - $$(cat .spike_session_start) ) / 60 ))" >> ../.spike_sessions.log && rm .spike_session_start && echo "Session logged" || echo "No session in progress"

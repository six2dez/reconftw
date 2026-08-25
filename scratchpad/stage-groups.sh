#!/usr/bin/env bash
# Regroup the phase-15/16 staged set into reviewable chunks.
# THIS SCRIPT NEVER COMMITS. It only stages + shows a diff for review.
# Usage:  bash scratchpad/stage-groups.sh list
#         bash scratchpad/stage-groups.sh show 1
#         bash scratchpad/stage-groups.sh stage 1      # stage only chunk 1
#         bash scratchpad/stage-groups.sh stage-all    # restore all 78 code paths
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

g1() { cat <<'P'
internal/core/backend/recorder.go
internal/core/backend/recorder_test.go
internal/core/backend/runner.go
internal/core/backend/local.go
internal/core/backend/tool_timeout_test.go
internal/core/backend/stderr_terminal_test.go
internal/core/backend/smoke_test.go
internal/core/errors/errors.go
P
}
g2() { cat <<'P'
internal/core/backend/argvector_drift_test.go
internal/core/backend/argvector_probes_test.go
internal/core/backend/toolflags_test.go
internal/core/backend/realtools_census_test.go
internal/core/backend/backend_realtools_test.go
internal/core/backend/tools.lock
P
}
g3() { cat <<'P'
internal/core/appctx/appctx.go
internal/core/appctx/appctx_test.go
internal/core/appctx/boot.go
internal/core/config/loader.go
internal/core/config/resolver_paths_test.go
internal/core/resolvers/ensure.go
internal/core/resolvers/ensure_test.go
internal/core/resolvers/gen.go
internal/core/scheduler/scheduler_test.go
internal/core/task/task.go
internal/core/task/result_reason_test.go
internal/core/ui/progress.go
internal/core/ui/progress_test.go
internal/mcp/handlers/common.go
internal/mcp/handlers/composite.go
internal/mcp/handlers/handlers_test.go
internal/mcp/handlers/monitor_test.go
internal/mcp/handlers/require_resolvers_test.go
internal/mcp/handlers/subs.go
P
}
g4() { cat <<'P'
internal/modules/subdomains/brute.go
internal/modules/subdomains/passive.go
internal/modules/subdomains/permut.go
internal/modules/subdomains/recursive.go
internal/modules/subdomains/resolve.go
internal/modules/subdomains/resolve_test.go
internal/modules/subdomains/resolver_gate_test.go
internal/modules/subdomains/stream_terminal_test.go
internal/modules/subdomains/takeover.go
internal/modules/subdomains/takeover_reason_test.go
internal/modules/subdomains/token_redaction_test.go
P
}
g5() { cat <<'P'
internal/modules/output_contract_test.go
internal/modules/silent_success_test.go
internal/modules/testdata/outputcontract/decoders.go
internal/modules/testdata/outputcontract/fixtures/sidecar_covered.json
internal/modules/testdata/outputcontract/fixtures/sidecar_covered.json.provenance
internal/modules/testdata/outputcontract/fixtures/with_provenance.jsonl
internal/modules/testdata/outputcontract/fixtures/without_provenance.jsonl
internal/modules/testdata/silentsuccess/bad_shapes.go
internal/modules/testdata/silentsuccess/good_shapes.go
internal/modules/web/artefact_publish_test.go
internal/modules/web/ffuf_real_fixture_test.go
internal/modules/web/httpx.go
internal/modules/web/httpx_real_fixture_test.go
internal/modules/web/merge.go
internal/modules/web/merge_hosts_test.go
internal/modules/web/no_silent_success_test.go
internal/modules/web/parity_test.go
internal/modules/web/uncommon_ports.go
internal/modules/web/uncommon_ports_test.go
internal/modules/web/testdata/fixtures/ffuf/ffuf_local_capture.json
internal/modules/web/testdata/fixtures/ffuf/ffuf_local_capture.json.provenance
internal/modules/web/testdata/httpx_real_output.jsonl
P
}
g6() { cat <<'P'
cmd/reconftw/composite_subcommands.go
cmd/reconftw/e2e_binary_test.go
cmd/reconftw/hermetic_resolvers_test.go
cmd/reconftw/release_gates_test.go
cmd/reconftw/stateful_subcommands.go
cmd/reconftw/stub_subcommands.go
cmd/reconftw/tool_recorder_e2e_test.go
Makefile
MIGRATION.md
scripts/parity-full.sh
scripts/pd-update-check-probe.sh
scripts/release-gates.sh
P
}
name() { case "$1" in
1) echo "backend: tool recorder + runner/local seam + terminal stderr (16-01)";;
2) echo "backend: arg-vector census, drift + flag guards, tools.lock (16-04/16-05)";;
3) echo "kernel: appctx/config/resolvers/task/ui/mcp plumbing (15 + 16-02)";;
4) echo "modules/subdomains: resolver gate, takeover reason, token redaction";;
5) echo "modules/web + module-wide contract & silent-success ratchets (16-02/16-07)";;
6) echo "cmd + build + scripts: release gates, parity harness, PD probe";;
esac; }

case "${1:-list}" in
  list)
    for i in 1 2 3 4 5 6; do printf "chunk %s  %-3s files  %s\n" "$i" "$(g$i | wc -l | tr -d ' ')" "$(name $i)"; done
    echo
    echo "NOTE: .planning/ROADMAP.md and .planning/STATE.md are staged but are NOT in any chunk."
    echo "      .planning/ is gitignored (.gitignore:65); those two are grandfathered-tracked."
    echo "      To drop them from the commit:  git restore --staged .planning/ROADMAP.md .planning/STATE.md"
    ;;
  show)   git --no-pager diff --cached --stat -- $(g${2} | tr '\n' ' ') ;;
  stage)  git reset -q && git add -- $(g${2} | tr '\n' ' ') && git status --short ;;
  stage-all)
    git reset -q
    for i in 1 2 3 4 5 6; do git add -- $(g$i | tr '\n' ' '); done
    echo "staged: $(git diff --cached --name-only | wc -l | tr -d ' ') code paths (.planning/ excluded)"
    ;;
  *) echo "usage: $0 {list|show N|stage N|stage-all}" >&2; exit 2 ;;
esac

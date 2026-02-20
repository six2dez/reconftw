#!/usr/bin/env bats

setup() {
  source "$(cd "$(dirname "$BATS_TEST_FILENAME")" && pwd)/../helpers/common.bash"
  setup_recon_env
}

@test "apply_performance_profile sets numeric values for low profile" {
  export PERF_PROFILE="low"
  unset PARALLEL_MAX_JOBS
  run apply_performance_profile
  [ "$status" -eq 0 ]
  [[ "$PARALLEL_MAX_JOBS" =~ ^[0-9]+$ ]]
  [[ "$FFUF_THREADS" =~ ^[0-9]+$ ]]
  [ "$PARALLEL_MAX_JOBS" -ge 1 ]
}

@test "apply_performance_profile max profile is not lower than low profile ffuf" {
  export PERF_PROFILE="low"
  apply_performance_profile >/dev/null
  low_ffuf="$FFUF_THREADS"

  export PERF_PROFILE="max"
  run apply_performance_profile
  [ "$status" -eq 0 ]
  [ "$FFUF_THREADS" -ge "$low_ffuf" ]
}

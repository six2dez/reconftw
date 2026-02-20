#!/usr/bin/env bats

setup() {
  local project_root
  project_root="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
  export SCRIPTPATH="$project_root"
  export LOGFILE="/dev/null"
  export bred='' bblue='' bgreen='' byellow='' yellow='' reset=''

  export TEST_DIR="$BATS_TEST_TMPDIR/reconftw_webs_all"
  mkdir -p "$TEST_DIR"
  cd "$TEST_DIR"

  source "$project_root/reconftw.sh" --source-only
}

teardown() {
  [[ -d "$TEST_DIR" ]] && rm -rf "$TEST_DIR"
}

@test "ensure_webs_all creates webs/webs_all.txt from webs/webs.txt" {
  mkdir -p webs
  printf "https://a.example.com\n" > webs/webs.txt
  rm -f webs/webs_uncommon_ports.txt

  run ensure_webs_all
  [ "$status" -eq 0 ]
  [ -f "webs/webs_all.txt" ]
  grep -q "https://a.example.com" "webs/webs_all.txt"
}


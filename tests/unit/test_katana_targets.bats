#!/usr/bin/env bats

setup() {
  local project_root
  project_root="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
  export SCRIPTPATH="$project_root"
  export LOGFILE="/dev/null"
  export bred='' bblue='' bgreen='' byellow='' yellow='' reset=''
  export domain="kavkom.com"
  export DEEP=false
  export DEEP_LIMIT2=1500
  export KATANA_DOMAIN_SEED=true
  export KATANA_TARGET_LIMIT=5

  export TEST_DIR="$BATS_TEST_TMPDIR/reconftw_katana"
  mkdir -p "$TEST_DIR"
  cd "$TEST_DIR"

  source "$project_root/reconftw.sh" --source-only
  source "$project_root/modules/web.sh"
}

teardown() {
  [[ -d "$TEST_DIR" ]] && rm -rf "$TEST_DIR"
}

@test "_katana_normalize_targets adds https scheme to bare hosts" {
  printf 'kavkom.com\nhttps://www.kavkom.com\n' > hosts.txt
  _katana_normalize_targets hosts.txt out.txt
  grep -qx 'https://kavkom.com' out.txt
  grep -qx 'https://www.kavkom.com' out.txt
}

@test "_katana_build_target_list seeds apex domain like katana -u" {
  mkdir -p webs
  : >webs/webs_all.txt
  _katana_build_target_list webs/webs_all.txt .tmp/katana_targets_effective.txt
  grep -qx 'https://kavkom.com' .tmp/katana_targets_effective.txt
  grep -qx 'https://www.kavkom.com' .tmp/katana_targets_effective.txt
}

@test "_katana_build_target_list caps large target sets when not DEEP" {
  mkdir -p webs
  for i in $(seq 1 10); do
    printf 'https://host%02d.kavkom.com\n' "$i" >>webs/webs_all.txt
  done
  _katana_build_target_list webs/webs_all.txt .tmp/katana_targets_effective.txt
  [ "$(wc -l <.tmp/katana_targets_effective.txt | tr -d ' ')" -eq 5 ]
  grep -qx 'https://kavkom.com' .tmp/katana_targets_effective.txt
}

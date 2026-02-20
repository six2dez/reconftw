#!/usr/bin/env bash
set -eo pipefail

setup_recon_env() {
  local project_root
  project_root="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
  export SCRIPTPATH="$project_root"
  export tools="${tools:-$HOME/Tools}"
  export LOGFILE="${LOGFILE:-/dev/null}"
  export bred='' bblue='' bgreen='' byellow='' yellow='' reset=''
  export NOTIFICATION=false
  export AXIOM=false
  source "$project_root/reconftw.sh" --source-only
}

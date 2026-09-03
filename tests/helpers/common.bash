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

  # reconftw.sh:7 runs `set +e`, so sourcing it DISABLES errexit in the test
  # shell — and bats needs errexit to fail a test at its first failing command.
  # Without this restore only a body's LAST command decides the verdict and every
  # assertion above it is inert: a literal `[ 1 -eq 0 ]` mid-test still reports
  # `ok`. The `set -eo pipefail` at the top of this file runs BEFORE the source
  # and does not survive it, which is why the restore belongs here.
  set -eo pipefail
}

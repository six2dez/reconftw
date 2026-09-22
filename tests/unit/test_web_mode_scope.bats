#!/usr/bin/env bats
#
# Regression coverage for issue #1045.
#
# prepare_web_mode_scope() picks between two very different behaviours:
#   -l <file>   wipe $dir and install the sanitized list as the new scope
#   -d <domain> preserve prior recon state and append the domain via anew
#
# It selected on $list, which start() REASSIGNS mid-run: under AXIOM with -d it
# writes the domain to target.txt and points $list at it. So
# `reconftw.sh -d example.com -w -v 50` took the -l branch with $flist still
# empty, `cp "" <tmp>` failed, and the run aborted before webs_menu with
# "Web mode scope preparation failed (tmpfile/cp error)".
#
# $flist is the correct signal: reconftw.sh sets it once at startup and leaves it
# empty for -d, so it means "the user passed a list" for the whole run. Both
# directions are pinned — a fix that made -d work by breaking -l is still a
# regression.
#
# ASSERTION STYLE, deliberately: every check is chained into the SINGLE final
# expression of the test. This runner does not abort a test body on the first
# failing command, so an assertion written on its own line mid-body is decorative
# — it prints nothing and changes no verdict. Verified while writing this file:
# a literal `[ 1 -eq 0 ]` placed at the top of a test still reported `ok`. Keep
# the chain; do not "tidy" these into separate statements.

setup() {
  local project_root
  project_root="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
  export SCRIPTPATH="$project_root"
  export LOGFILE="/dev/null"
  export bred='' bblue='' bgreen='' byellow='' yellow='' reset=''
  cd "$BATS_TEST_TMPDIR"
  source "$project_root/reconftw.sh" --source-only
  # reconftw.sh:7 runs `set +e`, which disables errexit in THIS shell. bats needs
  # errexit to fail a test at the first failing command; without it only the
  # body's last command decides the verdict and every earlier assertion is
  # inert. Restore it, or the checks below are decoration.
  set -e
}

@test "prepare_web_mode_scope takes the -d path when AXIOM reassigned list (issue #1045)" {
  export dir="$PWD/example.com"
  mkdir -p "$dir"
  export domain="example.com"
  # Exactly the state start() leaves under AXIOM + -d.
  export list="$dir/target.txt"
  export flist=''
  printf '%s\n' "$domain" > "$list"

  prepare_web_mode_scope \
    && [ -f "$dir/subdomains/subdomains.txt" ] \
    && grep -qx "example.com" "$dir/subdomains/subdomains.txt"
}

@test "prepare_web_mode_scope preserves prior recon state on the -d path" {
  export dir="$PWD/example.com"
  mkdir -p "$dir/hosts" "$dir/vulns"
  printf '203.0.113.7\n' > "$dir/hosts/ips.txt"
  printf 'prior finding\n' > "$dir/vulns/xss.txt"
  export domain="example.com"
  export list="$dir/target.txt"
  export flist=''
  printf '%s\n' "$domain" > "$list"

  # The -l path wipes $dir, so taking it here destroys prior -a/-s/-p output.
  prepare_web_mode_scope \
    && [ -f "$dir/hosts/ips.txt" ] \
    && [ -f "$dir/vulns/xss.txt" ]
}

@test "prepare_web_mode_scope still installs an -l list as the scope" {
  export dir="$PWD/multi"
  mkdir -p "$dir"
  export domain=''
  export flist="$PWD/targets.txt"
  printf 'a.example.com\nb.example.com\n' > "$flist"
  export list="$flist"

  prepare_web_mode_scope \
    && grep -qx "a.example.com" "$dir/subdomains/subdomains.txt" \
    && grep -qx "b.example.com" "$dir/subdomains/subdomains.txt"
}

#!/usr/bin/env bash
# spike/corpus/mock_stubborn_tool.sh
# Sleeps forever; spawns 2 children that also sleep forever; all 3 ignore SIGTERM.
# Used by the kill-tree synthetic-mock unit test in both spikes.
# Each spike's TestKillTree_SyntheticMock spawns this script under the spike's
# subprocess wrapper, then SIGINT the spike. Within 10s, pgrep -f mock_stubborn_tool
# MUST return nothing (SIGKILL via process-group escalation worked).
#
# Source: .planning/phases/01-language-adr-spike/01-RESEARCH.md Example 3
#         derived from lib/parallel.sh:_kill_tree() canonical bash pattern
trap '' TERM
( trap '' TERM; sleep 3600 ) &
( trap '' TERM; sleep 3600 ) &
sleep 3600

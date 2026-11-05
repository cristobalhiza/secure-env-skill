#!/usr/bin/env bash
# list-env-keys — shows the variables in .env files WITHOUT their secret values.
#
#   list-env-keys.sh [file.env ...]
#
# With no arguments it lists every .env in the project. Secrets show up as
# [secret, len=N]; public or non-sensitive variables show their value.
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

case "${1:-}" in -h|--help) sed -n '2,7p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;; esac

if [ $# -gt 0 ]; then list="$(printf '%s\n' "$@" | se_join)"; else list="$(se_discover | se_join)"; fi
SE_ENVFILES="$list" se_awk -v MODE=list

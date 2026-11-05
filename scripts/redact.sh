#!/usr/bin/env bash
# redact — shows files (or stdin) with secrets replaced by [REDACTED:NAME].
#
#   redact.sh file [file ...]
#   command | redact.sh
#
# Use it to read logs, saved responses or the .env itself without exposing values.
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

case "${1:-}" in -h|--help) sed -n '2,7p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;; esac

SE_ENVFILES="$( { se_discover; [ $# -gt 0 ] && for f in "$@"; do se_is_env_file "$f" && printf '%s\n' "$f"; done; } | se_join)"
export SE_ENVFILES
status=0
if [ $# -eq 0 ]; then se_awk -v MODE=redact; exit $?; fi
for f in "$@"; do
  if [ ! -r "$f" ] || [ -d "$f" ]; then echo "redact: cannot read $f" >&2; status=1; continue; fi
  [ $# -gt 1 ] && printf '==> %s <==\n' "$f"
  se_awk -v MODE=redact "$f" || status=$?
done
exit $status

#!/usr/bin/env bash
# redact — muestra archivos (o stdin) con los secretos reemplazados por [REDACTED:NOMBRE].
#
#   redact.sh archivo [archivo ...]
#   comando | redact.sh
#
# Úsalo para leer logs, respuestas guardadas o el propio .env sin exponer valores.
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

case "${1:-}" in -h|--help) sed -n '2,7p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;; esac

SE_ENVFILES="$( { se_discover; [ $# -gt 0 ] && for f in "$@"; do se_is_env_file "$f" && printf '%s\n' "$f"; done; } | se_join)"
export SE_ENVFILES
status=0
if [ $# -eq 0 ]; then se_awk -v MODE=redact; exit $?; fi
for f in "$@"; do
  if [ ! -r "$f" ] || [ -d "$f" ]; then echo "redact: no se puede leer $f" >&2; status=1; continue; fi
  [ $# -gt 1 ] && printf '==> %s <==\n' "$f"
  se_awk -v MODE=redact "$f" || status=$?
done
exit $status

#!/usr/bin/env bash
# list-env-keys — muestra las variables de los .env SIN sus valores secretos.
#
#   list-env-keys.sh [archivo.env ...]
#
# Sin argumentos lista todos los .env del proyecto. Los secretos aparecen como
# [secreto, len=N]; las variables públicas o no sensibles muestran su valor.
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

case "${1:-}" in -h|--help) sed -n '2,7p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;; esac

if [ $# -gt 0 ]; then list="$(printf '%s\n' "$@" | se_join)"; else list="$(se_discover | se_join)"; fi
SE_ENVFILES="$list" se_awk -v MODE=list

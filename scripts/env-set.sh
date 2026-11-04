#!/usr/bin/env bash
# env-set — agrega, actualiza o elimina una variable en un .env sin mostrar su contenido.
#
#   env-set.sh [-f archivo] CLAVE VALOR
#   env-set.sh [-f archivo] CLAVE --generate [bytes]   # secreto aleatorio en hex (32 bytes por defecto)
#   env-set.sh [-f archivo] CLAVE --unset
#
# Archivo por defecto: ./.env (se crea con permisos 600 si no existe). Conserva comentarios,
# orden y el resto de las variables. Nunca imprime el valor.
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

usage() { sed -n '2,9p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

file=./.env
case "${1:-}" in -h|--help|"") usage; exit 0 ;; esac
if [ "${1:-}" = "-f" ] || [ "${1:-}" = "--file" ]; then file="${2:-}"; shift 2; fi
key="${1:-}"; shift || true

if ! printf '%s' "$key" | grep -Eq '^[A-Za-z_][A-Za-z0-9_]*$'; then
  echo "env-set: nombre de variable inválido: '$key'" >&2; exit 64
fi

unset_mode=0; value=""; what="actualizada"
case "${1:-}" in
  --unset) unset_mode=1; what="eliminada" ;;
  --generate)
    bytes="${2:-32}"
    case "$bytes" in ''|*[!0-9]*) echo "env-set: bytes inválidos: $bytes" >&2; exit 64 ;; esac
    if command -v openssl >/dev/null 2>&1; then value="$(openssl rand -hex "$bytes")"
    else value="$(od -An -tx1 -N "$bytes" /dev/urandom | tr -d ' \n')"; fi
    what="generada ($bytes bytes en hex)" ;;
  "") echo "env-set: falta el valor (o usa --generate / --unset)" >&2; exit 64 ;;
  *) value="$1" ;;
esac

if [ ! -e "$file" ]; then
  [ "$unset_mode" = 1 ] && { echo "env-set: $file no existe; nada que eliminar."; exit 0; }
  ( umask 077; : > "$file" )
fi

tmp="$(mktemp "${TMPDIR:-/tmp}/secure-env.XXXXXX")" || exit 1
trap 'rm -f "$tmp"' EXIT
chmod 600 "$tmp"
SE_SET_FILE="$file" SE_SET_KEY="$key" SE_SET_VALUE="$value" SE_SET_UNSET="$unset_mode" \
  se_awk -v MODE=set > "$tmp" || { echo "env-set: no se pudo procesar $file" >&2; exit 1; }
# cat > conserva permisos, dueño y enlaces del archivo original
cat "$tmp" > "$file"
if [ "$unset_mode" = 1 ]; then echo "OK: $key $what en $file."
else echo "OK: $key $what en $file (len=${#value})."; fi

#!/usr/bin/env bash
# run-secure — ejecuta un comando con las variables de .env cargadas y redacta su salida.
#
#   run-secure.sh [-f archivo.env]... [--no-env] -- '<línea de shell>'
#   run-secure.sh [-f archivo.env]... [--no-env] -- <comando> [args...]
#
# - Con UN solo argumento con espacios, se ejecuta como línea de shell (bash -c). Ponla entre
#   comillas SIMPLES para que $VARIABLES se expandan adentro, con el .env ya cargado.
# - Sin -f carga ./.env y ./.env.local (si no hay ninguno, los de la raíz del proyecto).
# - stdout y stderr pasan por el redactor: cada valor secreto de CUALQUIER .env del proyecto
#   (y de variables sensibles heredadas, ej. GITHUB_TOKEN) se reemplaza por [REDACTED:NOMBRE],
#   también en sus formas JSON-escapada, URL-encoded y base64.
# - El código de salida es el del comando. stdin se pasa tal cual.
#
# Ejemplos:
#   run-secure.sh -- 'curl -sS -H "Authorization: Bearer $HUBSPOT_TOKEN" https://api.hubapi.com/crm/v3/objects/contacts?limit=1'
#   run-secure.sh -- 'curl -sS -X POST "$N8N_WEBHOOK_URL" -d @payload.json'
#   run-secure.sh -f .env.production -- node scripts/sync.js
set -uo pipefail

. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

usage() { sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

files=()
load=1
while [ $# -gt 0 ]; do
  case "$1" in
    -f|--env-file) [ $# -ge 2 ] || { echo "run-secure: falta la ruta después de $1" >&2; exit 64; }; files+=("$2"); shift 2 ;;
    --env-file=*) files+=("${1#*=}"); shift ;;
    --no-env) load=0; shift ;;
    -h|--help) usage; exit 0 ;;
    --) shift; break ;;
    *) break ;;
  esac
done

if [ $# -eq 0 ]; then
  echo "run-secure: falta el comando. Uso: run-secure.sh [-f archivo.env] -- '<línea de shell>'" >&2
  exit 64
fi

# Un único argumento con espacios = línea de shell
if [ $# -eq 1 ]; then
  case "$1" in *[[:space:]]*) set -- bash -c "$1" ;; esac
fi

# Por defecto: .env y luego .env.local (que pisa) de la carpeta actual; si no hay, los de la raíz.
if [ "$load" = 1 ] && [ ${#files[@]} -eq 0 ]; then
  for dir in . "$(se_root)"; do
    [ -f "$dir/.env" ] && files+=("$dir/.env")
    [ -f "$dir/.env.local" ] && files+=("$dir/.env.local")
    [ ${#files[@]} -gt 0 ] && break
  done
fi

for f in ${files[@]+"${files[@]}"}; do
  if [ ! -f "$f" ]; then echo "run-secure: no existe el archivo $f" >&2; exit 66; fi
done

# 1) Exportar variables (el valor viaja escapado en una línea y se decodifica con %b)
if [ ${#files[@]} -gt 0 ]; then
  envlist="$(printf '%s\n' "${files[@]}" | se_join)"
  while IFS=$'\t' read -r k v; do
    [ -n "$k" ] || continue
    printf -v val '%b' "$v"
    export "$k=$val"
  done < <(SE_ENVFILES="$envlist" se_awk -v MODE=export)
  unset k v val
fi

# 2) Fuentes de redacción: todos los .env del proyecto + los cargados
SE_ENVFILES="$( { se_discover; [ ${#files[@]} -gt 0 ] && printf '%s\n' "${files[@]}"; } | se_join)"
export SE_ENVFILES

redact() { se_awk -v MODE=redact; }

# 3) Ejecutar: stdout -> redactor -> stdout ; stderr -> redactor -> stderr
#    (sin process substitution, para que funcione igual en bash 3.2 de macOS)
{ { "$@" 2>&1 1>&4 4>&- | redact >&2 4>&-; } 4>&1 | redact; }
exit $?

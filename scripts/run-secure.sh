#!/usr/bin/env bash
# run-secure — runs a command with the .env variables loaded and redacts its output.
#
#   run-secure.sh [-f file.env]... [--no-env] -- '<shell line>'
#   run-secure.sh [-f file.env]... [--no-env] -- <command> [args...]
#
# - With a SINGLE argument containing spaces, it runs as a shell line (bash -c). Put it in
#   SINGLE quotes so $VARIABLES expand inside, with the .env already loaded.
# - Without -f it loads ./.env and ./.env.local (if there are none, the ones at the project root).
# - stdout and stderr go through the redactor: every secret value from ANY .env in the project
#   (and from inherited sensitive variables, e.g. GITHUB_TOKEN) is replaced by [REDACTED:NAME],
#   also in its JSON-escaped, URL-encoded and base64 forms.
# - The exit code is the command's. stdin is passed through as is.
#
# Examples:
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
    -f|--env-file) [ $# -ge 2 ] || { echo "run-secure: missing path after $1" >&2; exit 64; }; files+=("$2"); shift 2 ;;
    --env-file=*) files+=("${1#*=}"); shift ;;
    --no-env) load=0; shift ;;
    -h|--help) usage; exit 0 ;;
    --) shift; break ;;
    *) break ;;
  esac
done

if [ $# -eq 0 ]; then
  echo "run-secure: missing command. Usage: run-secure.sh [-f file.env] -- '<shell line>'" >&2
  exit 64
fi

# A single argument with spaces = shell line
if [ $# -eq 1 ]; then
  case "$1" in *[[:space:]]*) set -- bash -c "$1" ;; esac
fi

# Default: .env and then .env.local (which overrides) from the current folder; if none, the root's.
if [ "$load" = 1 ] && [ ${#files[@]} -eq 0 ]; then
  for dir in . "$(se_root)"; do
    [ -f "$dir/.env" ] && files+=("$dir/.env")
    [ -f "$dir/.env.local" ] && files+=("$dir/.env.local")
    [ ${#files[@]} -gt 0 ] && break
  done
fi

for f in ${files[@]+"${files[@]}"}; do
  if [ ! -f "$f" ]; then echo "run-secure: file not found: $f" >&2; exit 66; fi
done

# 1) Export variables (the value travels escaped on one line and is decoded with %b)
if [ ${#files[@]} -gt 0 ]; then
  envlist="$(printf '%s\n' "${files[@]}" | se_join)"
  while IFS=$'\t' read -r k v; do
    [ -n "$k" ] || continue
    printf -v val '%b' "$v"
    export "$k=$val"
  done < <(SE_ENVFILES="$envlist" se_awk -v MODE=export)
  unset k v val
fi

# 2) Redaction sources: every .env in the project + the loaded ones
SE_ENVFILES="$( { se_discover; [ ${#files[@]} -gt 0 ] && printf '%s\n' "${files[@]}"; } | se_join)"
export SE_ENVFILES

redact() { se_awk -v MODE=redact; }

# 3) Run: stdout -> redactor -> stdout ; stderr -> redactor -> stderr
#    (no process substitution, so it works the same on macOS's bash 3.2)
{ { "$@" 2>&1 1>&4 4>&- | redact >&2 4>&-; } 4>&1 | redact; }
exit $?

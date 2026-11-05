#!/usr/bin/env bash
# env-set — adds, updates or removes a variable in a .env without showing its content.
#
#   env-set.sh [-f file] KEY VALUE
#   env-set.sh [-f file] KEY --generate [bytes]   # random hex secret (32 bytes by default)
#   env-set.sh [-f file] KEY --unset
#
# Default file: ./.env (created with mode 600 if it doesn't exist). Keeps comments,
# order and the other variables. Never prints the value.
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

usage() { sed -n '2,9p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

file=./.env
case "${1:-}" in -h|--help|"") usage; exit 0 ;; esac
if [ "${1:-}" = "-f" ] || [ "${1:-}" = "--file" ]; then file="${2:-}"; shift 2; fi
key="${1:-}"; shift || true

if ! printf '%s' "$key" | grep -Eq '^[A-Za-z_][A-Za-z0-9_]*$'; then
  echo "env-set: invalid variable name: '$key'" >&2; exit 64
fi

unset_mode=0; value=""; what="updated"
case "${1:-}" in
  --unset) unset_mode=1; what="removed" ;;
  --generate)
    bytes="${2:-32}"
    case "$bytes" in ''|*[!0-9]*) echo "env-set: invalid bytes: $bytes" >&2; exit 64 ;; esac
    if command -v openssl >/dev/null 2>&1; then value="$(openssl rand -hex "$bytes")"
    else value="$(od -An -tx1 -N "$bytes" /dev/urandom | tr -d ' \n')"; fi
    what="generated ($bytes bytes in hex)" ;;
  "") echo "env-set: missing value (or use --generate / --unset)" >&2; exit 64 ;;
  *) value="$1" ;;
esac

if [ ! -e "$file" ]; then
  [ "$unset_mode" = 1 ] && { echo "env-set: $file doesn't exist; nothing to remove."; exit 0; }
  ( umask 077; : > "$file" )
fi

tmp="$(mktemp "${TMPDIR:-/tmp}/secure-env.XXXXXX")" || exit 1
trap 'rm -f "$tmp"' EXIT
chmod 600 "$tmp"
SE_SET_FILE="$file" SE_SET_KEY="$key" SE_SET_VALUE="$value" SE_SET_UNSET="$unset_mode" \
  se_awk -v MODE=set > "$tmp" || { echo "env-set: could not process $file" >&2; exit 1; }
# cat > keeps the original file's permissions, owner and links
cat "$tmp" > "$file"
if [ "$unset_mode" = 1 ]; then echo "OK: $key $what in $file."
else echo "OK: $key $what in $file (len=${#value})."; fi

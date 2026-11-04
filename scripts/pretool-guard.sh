#!/usr/bin/env bash
# pretool-guard — hook PreToolUse de Claude Code para secure-env.
#
# Recibe el JSON del tool call por stdin y:
#   - lo deja pasar (exit 0, sin salida),
#   - lo bloquea con un mensaje accionable para Claude (exit 2, mensaje en stderr), o
#   - pide confirmación al usuario (JSON con permissionDecision "ask") cuando un archivo
#     que se va a leer contiene el valor de un secreto.
#
# Ante un error interno no bloquea (fail-open) y deja un aviso en stderr: un guardia roto
# no debe frenar el trabajo; los permisos "deny" de settings.json siguen activos.
set -u

SE_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SE_HERE/lib/common.sh" || exit 0

payload="$(cat)"
[ -n "$payload" ] || exit 0

SE_ENVFILES="$(se_discover | se_join)"
SE_SCRIPTS_REL="$(se_scripts_rel)"
export SE_ENVFILES SE_SCRIPTS_REL

decision="$(printf '%s' "$payload" | LC_ALL=C awk -v MODE=hook -f "$SE_LIB/engine.awk" -f "$SE_LIB/guard.awk" 2>/dev/null)"
rc=$?
if [ $rc -ne 0 ] || [ -z "$decision" ]; then
  echo "secure-env: el guardia no pudo analizar este tool call (rc=$rc); se dejó pasar." >&2
  exit 0
fi

verdict="${decision%%$'\t'*}"
reason="${decision#*$'\t'}"

json_str() {
  local s="$1"
  s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\n'/\\n}"; s="${s//$'\t'/ }"; s="${s//$'\r'/}"
  printf '"%s"' "$s"
}

case "$verdict" in
  ALLOW) exit 0 ;;
  DENY)  printf '%s\n' "$reason" >&2; exit 2 ;;
  ASK)
    printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":%s}}\n' "$(json_str "$reason")"
    exit 0 ;;
  *) exit 0 ;;
esac

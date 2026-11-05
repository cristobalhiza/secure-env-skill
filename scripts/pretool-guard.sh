#!/usr/bin/env bash
# pretool-guard — Claude Code PreToolUse hook for secure-env.
#
# Receives the tool call JSON on stdin and:
#   - lets it through (exit 0, no output),
#   - blocks it with an actionable message for Claude (exit 2, message on stderr), or
#   - asks the user for confirmation (JSON with permissionDecision "ask") when a file
#     about to be read contains a secret value.
#
# On an internal error it doesn't block (fail-open) and leaves a notice on stderr: a broken
# guard shouldn't stop work; the "deny" permissions in settings.json stay active.
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
  echo "secure-env: the guard could not parse this tool call (rc=$rc); it was let through." >&2
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

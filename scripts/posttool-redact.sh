#!/usr/bin/env bash
# posttool-redact — Claude Code PostToolUse hook for secure-env (safety net).
#
# Receives the result of any tool and, if it contains a secret value (from the project's
# .env files or from sensitive environment variables), replaces it with [REDACTED:NAME]
# BEFORE Claude sees it, using updatedToolOutput with the same JSON shape as the original.
#
# Covers what the PreToolUse hook can't foresee: your own script printing its config,
# a log carrying a token, an API response echoing the credential, an MCP, etc.
# If there's nothing to redact, it prints nothing (zero effect).
set -u

SE_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SE_HERE/lib/common.sh" || exit 0

payload="$(cat)"
[ -n "$payload" ] || exit 0

SE_ENVFILES="$(se_discover | se_join)"
export SE_ENVFILES

result="$(printf '%s' "$payload" | LC_ALL=C awk -v MODE=post -f "$SE_LIB/engine.awk" -f "$SE_LIB/guard.awk" 2>/dev/null)" || exit 0

case "$result" in
  REDACTED$'\t'*) ;;
  *) exit 0 ;;
esac

rest="${result#REDACTED$'\t'}"
keys="${rest%%$'\t'*}"
redacted="${rest#*$'\t'}"
SP="$(se_scripts_rel)"

printf '{"hookSpecificOutput":{"hookEventName":"PostToolUse","updatedToolOutput":%s,"additionalContext":"secure-env redacted the values of %s in this tool result; they appear as [REDACTED:NAME]. The real values are still in the environment: commands run through bash %s/run-secure.sh can use them."},"systemMessage":"secure-env: redacted %s in the tool output."}\n' \
  "$redacted" "$keys" "$SP" "$keys"
exit 0

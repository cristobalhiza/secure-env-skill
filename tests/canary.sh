#!/usr/bin/env bash
# canary — live test of the PostToolUse safety net.
#
# Prints the value of CANARY_TOKEN by reading the .env on its own (the PreToolUse hook doesn't
# see it coming, just like your own script logging its config). If the installation works,
# Claude must see [REDACTED:CANARY_TOKEN] and NOT the value.
#
# Setup (once):           bash .claude/skills/secure-env/scripts/env-set.sh CANARY_TOKEN --generate 16
# Test in Claude Code:    "run bash .claude/skills/secure-env/tests/canary.sh and tell me what it printed"
set -u
root="${CLAUDE_PROJECT_DIR:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"
val="$(LC_ALL=C awk -F= '$1 == "CANARY_TOKEN" { sub(/^[^=]*=/, ""); print; exit }' "$root/.env" 2>/dev/null)"
if [ -z "$val" ]; then
  echo "No CANARY_TOKEN in $root/.env. Create it with: bash .claude/skills/secure-env/scripts/env-set.sh CANARY_TOKEN --generate 16"
  exit 1
fi
echo "canary: $val"
echo "If you see [REDACTED:CANARY_TOKEN] above, the safety net works. If you see 32 hex characters, it isn't active."

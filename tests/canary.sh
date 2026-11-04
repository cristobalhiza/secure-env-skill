#!/usr/bin/env bash
# canary — prueba en vivo de la red de seguridad PostToolUse.
#
# Imprime el valor de CANARY_TOKEN leyendo el .env por su cuenta (el hook PreToolUse no lo
# ve venir, igual que un script propio que loguea su config). Si la instalación funciona,
# Claude debe ver [REDACTED:CANARY_TOKEN] y NO el valor.
#
# Preparación (una vez):  bash .claude/skills/secure-env/scripts/env-set.sh CANARY_TOKEN --generate 16
# Prueba en Claude Code:  "ejecuta bash .claude/skills/secure-env/tests/canary.sh y dime qué imprimió"
set -u
root="${CLAUDE_PROJECT_DIR:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"
val="$(LC_ALL=C awk -F= '$1 == "CANARY_TOKEN" { sub(/^[^=]*=/, ""); print; exit }' "$root/.env" 2>/dev/null)"
if [ -z "$val" ]; then
  echo "No hay CANARY_TOKEN en $root/.env. Créalo con: bash .claude/skills/secure-env/scripts/env-set.sh CANARY_TOKEN --generate 16"
  exit 1
fi
echo "canary: $val"
echo "Si arriba ves [REDACTED:CANARY_TOKEN], la red de seguridad funciona. Si ves 32 caracteres hex, no está activa."

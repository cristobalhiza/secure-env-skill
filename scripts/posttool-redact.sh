#!/usr/bin/env bash
# posttool-redact — hook PostToolUse de Claude Code para secure-env (red de seguridad).
#
# Recibe el resultado de cualquier herramienta y, si contiene el valor de un secreto (de los
# .env del proyecto o de variables sensibles del entorno), lo reemplaza por [REDACTED:NOMBRE]
# ANTES de que Claude lo vea, usando updatedToolOutput con la misma forma JSON del original.
#
# Cubre lo que el hook PreToolUse no puede prever: un script propio que imprime su config,
# un log que trae un token, una respuesta de API que repite la credencial, un MCP, etc.
# Si no hay nada que redactar, no imprime nada (cero efecto).
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

printf '{"hookSpecificOutput":{"hookEventName":"PostToolUse","updatedToolOutput":%s,"additionalContext":"secure-env redacted the values of %s in this tool result; they appear as [REDACTED:NAME]. The real values are still in the environment: commands run through bash %s/run-secure.sh can use them."},"systemMessage":"secure-env: se redactaron %s en la salida de la herramienta."}\n' \
  "$redacted" "$keys" "$SP" "$keys"
exit 0

# secure-env — funciones compartidas (bash 3.2+; macOS, Linux, WSL y Git Bash en Windows).
# shellcheck shell=bash

SE_LIB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SE_SCRIPTS="$(dirname "$SE_LIB")"
SE_SKILL="$(dirname "$SE_SCRIPTS")"

# shellcheck source=/dev/null
. "$SE_SKILL/config.sh"
# shellcheck source=/dev/null
[ -f "$SE_SKILL/config.local.sh" ] && . "$SE_SKILL/config.local.sh"

SE_SEP=$'\036'

se_awk() { LC_ALL=C awk -f "$SE_LIB/engine.awk" "$@"; }

# Convierte rutas estilo Windows (C:\x) a rutas de Git Bash cuando hace falta.
se_path() {
  case "$1" in
    [A-Za-z]:\\*|[A-Za-z]:/*) if command -v cygpath >/dev/null 2>&1; then cygpath -u "$1"; return; fi ;;
  esac
  printf '%s\n' "$1"
}

se_root() {
  if [ -n "${CLAUDE_PROJECT_DIR:-}" ]; then se_path "$CLAUDE_PROJECT_DIR"; return; fi
  git rev-parse --show-toplevel 2>/dev/null || pwd
}

se_is_env_file() {
  local b="${1##*/}"
  case "$b" in
    *.example|*.example.*|*.sample|*.sample.*|*.template|*.template.*|*.tpl|*.dist|*.defaults|*.schema) return 1 ;;
    example.env|sample.env|template.env|default.env|defaults.env) return 1 ;;
    .env|.envrc|.dev.vars|.env.*|.dev.vars.*|*.env) return 0 ;;
  esac
  return 1
}

# Imprime (una por línea) las rutas de archivos .env con secretos del proyecto y extras.
se_discover() {
  local root="${1:-$(se_root)}" f
  local findbin=find
  [ -x /usr/bin/find ] && findbin=/usr/bin/find
  if [ -d "$root" ]; then
    "$findbin" "$root" -maxdepth "${SECURE_ENV_SCAN_DEPTH:-4}" \
      \( -name node_modules -o -name .git -o -name vendor -o -name dist -o -name build -o -name .next \
         -o -name .nuxt -o -name .venv -o -name venv -o -name __pycache__ -o -name .terraform -o -name target \
         -o -name .turbo -o -name .cache -o -name coverage -o -name .output \) -prune \
      -o -type f \( -name '.env' -o -name '.env.*' -o -name '*.env' -o -name '.envrc' -o -name '.dev.vars' -o -name '.dev.vars.*' \) -print 2>/dev/null |
    while IFS= read -r f; do se_is_env_file "$f" && printf '%s\n' "$f"; done
  fi
  for f in ${SECURE_ENV_EXTRA_FILES:-}; do
    f="${f/#\~/$HOME}"
    [ -f "$f" ] && printf '%s\n' "$f"
  done
  return 0
}

# Une líneas de stdin con el separador \036.
se_join() {
  local out="" line
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    out="${out:+$out$SE_SEP}$line"
  done
  printf '%s' "$out"
}

# Ruta de los scripts relativa al proyecto, para los mensajes del hook.
se_scripts_rel() {
  local root; root="$(se_root)"
  case "$SE_SCRIPTS" in
    "$root"/*) printf '%s' "${SE_SCRIPTS#"$root"/}" ;;
    *) printf '%s' "$SE_SCRIPTS" ;;
  esac
}

#!/usr/bin/env bash
# Suite de pruebas de secure-env. No toca tu proyecto: crea uno falso en un directorio temporal.
#   bash .claude/skills/secure-env/tests/run-tests.sh
set -u

SKILL="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
S="$SKILL/scripts"
PROJ="$(mktemp -d "${TMPDIR:-/tmp}/secure-env-test.XXXXXX")"
trap 'rm -rf "$PROJ"' EXIT
export CLAUDE_PROJECT_DIR="$PROJ"
unset SECURE_ENV_PUBLIC_VARS SECURE_ENV_SECRET_VARS SECURE_ENV_STRICT SECURE_ENV_ALLOW_COMMANDS 2>/dev/null

pass=0; fail=0
ok()  { pass=$((pass + 1)); }
bad() { fail=$((fail + 1)); printf '  FALLA: %s\n' "$1"; [ -n "${2:-}" ] && printf '         %s\n' "$2"; }

# ---------------------------------------------------------------- proyecto de prueba
# Claves falsas armadas en dos pedazos ('sk_''live_…') para que el escaneo de secretos de GitHub no las tome por reales.
SECRET_KEY='sk_''live_9fA2kQ7mZx81LpR4vT6wY3bN'
HUB_TOKEN='pat-''na1-4b2c8e1f-9a7d-4c3b-8e2f-1a6d9c0b7e54'
DB_PASS='S3cr3tP4ss!w0rd'
WEBHOOK='https://n8n.example.com/webhook/7f3c2a91-5b8e-4d6f-a0c2-9e1b4d7a6f38'
cat > "$PROJ/.env" <<EOF
# credenciales
API_KEY=$SECRET_KEY
export HUBSPOT_TOKEN="$HUB_TOKEN"
DATABASE_URL=postgres://app:${DB_PASS}@db.internal:5432/main
N8N_WEBHOOK_URL=$WEBHOOK
PORT=3000
NODE_ENV=development
AWS_REGION=us-east-1
API_BASE_URL=https://api.hubapi.com
NEXT_PUBLIC_SITE=https://example.com
LOCAL_DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/dev
BETTER_AUTH_URL=http://localhost:3000
CONTACT_EMAIL=ops@example.com
PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\n-----END PRIVATE KEY-----"
EOF
mkdir -p "$PROJ/apps/api" "$PROJ/logs" "$PROJ/src"
printf 'STRIPE_SECRET=rk_''test_51HxYzAbCdEfGh0123456789\n' > "$PROJ/apps/api/.env.local"
printf 'API_KEY=\nPORT=3000\n' > "$PROJ/.env.example"
printf '{"ok":true,"echo":"%s"}\n' "$SECRET_KEY" > "$PROJ/logs/response.json"
printf 'console.log("hola")\n' > "$PROJ/src/app.js"
mkdir -p "$PROJ/docs"
printf 'Base local: postgres 16 (usuario postgres). App en http://localhost:3000\n' > "$PROJ/docs/DEPLOY.md"

jesc() { local s="$1"; s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\n'/\\n}"; s="${s//$'\t'/\\t}"; printf '%s' "$s"; }

hook() { # tool, campo, valor
  printf '{"session_id":"t","transcript_path":"/x/transcript_path.jsonl","cwd":"%s","hook_event_name":"PreToolUse","tool_name":"%s","tool_input":{"%s":"%s","description":"test"}}' \
    "$(jesc "$PROJ")" "$1" "$2" "$(jesc "$3")" | bash "$S/pretool-guard.sh" 2>"$PROJ/.stderr"
}

expect() { # decision tool campo valor
  local want="$1" out rc got
  out="$(hook "$2" "$3" "$4")"; rc=$?
  if [ $rc -eq 2 ]; then got=deny
  elif printf '%s' "$out" | grep -q '"permissionDecision":"ask"'; then got=ask
  else got=allow; fi
  if [ "$got" = "$want" ]; then ok; else bad "[$2] esperaba $want, obtuvo $got: $4" "$(head -c 300 "$PROJ/.stderr")"; fi
}
deny()  { expect deny  Bash command "$1"; }
allow() { expect allow Bash command "$1"; }
ask()   { expect ask   Bash command "$1"; }

echo "== Hook: debe BLOQUEAR"
deny 'cat .env'
deny 'head -5 apps/api/.env.local'
deny 'grep API .env'
deny 'source .env && node app.js'
deny '. ./.env; npm start'
deny 'set -a; source .env; set +a'
deny "python3 -c \"print(open('.env').read())\""
deny 'node --env-file=.env app.js'
deny 'docker run --env-file .env myimg'
deny 'npx dotenv -- node app.js'
deny 'python -m dotenv run -- node app.js'
deny 'env'
deny 'printenv'
deny 'env | grep KEY'
deny 'export -p'
deny 'declare -x'
deny 'set'
deny 'printenv API_KEY'
deny 'set -x; curl https://api.example.com'
deny 'set -euxo pipefail'
deny 'bash -x deploy.sh'
deny 'echo $API_KEY'
deny 'echo "token: ${HUBSPOT_TOKEN}"'
deny 'curl -sS -H "Authorization: Bearer $HUBSPOT_TOKEN" https://api.hubapi.com/crm/v3/objects/contacts'
deny 'curl -v --netrc https://api.example.com'
deny 'cat <<< "$API_KEY"'
deny $'cat <<EOF\nkey=$API_KEY\nEOF'
deny "node -e \"console.log(process.env)\""
deny "node -e \"console.log(process.env.API_KEY)\""
deny "python3 -c 'import os; print(os.environ)'"
deny "python3 -c 'import os; print(os.environ[\"HUBSPOT_TOKEN\"])'"
deny $'python3 - <<\'PY\'\nimport os\nprint(os.getenv("API_KEY"))\nPY'
deny "bash -c 'echo \$API_KEY'"
deny "sh -c 'cat .env'"
deny 'echo $(cat .env)'
deny 'X=`cat .env`; echo $X'
deny 'while read l; do echo "$l"; done < .env'
deny 'cp .env /tmp/backup.txt'
deny 'git diff .env'
deny 'git show HEAD:.env'
deny 'git add .env'
deny 'find . -name .env -exec cat {} \;'
deny 'cat config/prod.env'
deny 'pwsh -Command "Get-Content .env"'
deny 'pwsh -Command "Get-ChildItem env:"'
deny 'docker compose config'
deny 'docker inspect my-container'
deny 'docker exec api printenv'
deny 'cat ~/.ssh/id_ed25519'
deny 'sudo cat /app/.env'
deny 'cat .envrc'
deny 'gh auth token'
deny 'gh auth status --show-token'
deny 'aws configure get aws_secret_access_key'
deny 'security find-generic-password -s api -w'
deny 'op read op://vault/item/credential'
deny 'gcloud auth print-access-token'
deny 'kubectl get secret db-creds -o yaml'
deny 'heroku config -a myapp'

# grep recursivo sobre una carpeta con .env lo lee sin nombrarlo
deny 'grep -rn "TODO" .'
deny 'grep -r TODO'
deny 'grep -rn TODO apps/'
deny "grep -rn TODO --exclude='*.log' ."
deny 'rg --hidden TODO'
deny 'rg -uu TODO'
deny 'ack TODO'
# el .env sigue siendo ruta cuando no es el patrón ni texto
deny 'grep -e API .env'
deny 'grep -f .env src/app.js'
deny 'git commit -m "fix" .env'
# casos sintéticos (revisión de falsos positivos)
deny 'diff .env.example .env'
deny 'scp .env vps:/tmp/'

echo "== Hook: debe PERMITIR"
# git: el mensaje de -m es texto, no una ruta
allow 'git commit -m "no versionar .env"'
allow 'git commit --message="copiar .env.example"'
allow 'git commit -am "actualiza docs de .env"'
# grep: el patrón y las exclusiones no son rutas
allow 'grep -rn "\.env" src/ README.md'
allow 'grep -rn "TODO" src/'
allow "grep -rn TODO --exclude='.env*' ."
allow 'grep -rn TODO --exclude=.env --exclude=.env.local .'
allow "rg -n TODO -g '!.env*'"
allow 'rg -n TODO'
allow 'grep -n "API_KEY" src/app.js'
# archivos que solo mencionan valores triviales de .env (clave "postgres", origen de BETTER_AUTH_URL)
allow 'cat docs/DEPLOY.md'
# casos sintéticos (revisión de falsos positivos)
allow $'cat > notas.md <<\'EOF\'\nCopia .env.example a .env y completa\nEOF'
allow $'cat > cfg.py <<\'EOF\'\nfrom dotenv import load_dotenv\nload_dotenv(".env")\nEOF'
allow 'git log --oneline -- .env.example'
allow 'git status --short .env'
allow 'echo "Falta configurar .env"'
allow 'ls -la .env*'
allow 'wc -l .env'
allow 'sed -n 1,5p .env.example'
allow 'printf "%s\n" "DEBUG=1" >> .env'
allow 'ls -la'
allow 'npm run dev'
allow 'node app.js'
allow 'git status'
allow 'cp .env.example .env'
allow 'echo "PORT=3000" >> .env'
allow $'cat > .env <<\'EOF\'\nPORT=3000\nEOF'
allow 'echo ".env" >> .gitignore'
allow 'git check-ignore -q .env'
allow 'test -f .env && echo existe'
allow 'chmod 600 .env'
allow 'mv .env .env.bak'
allow 'cat .env.example'
allow 'echo $HOME $PATH'
allow 'echo ${#API_KEY}'
allow 'test -n "$API_KEY"'
allow 'printenv NODE_ENV'
allow "echo '\$API_KEY no se expande en comillas simples'"
allow 'grep -rn "process.env" src/'
allow 'source .venv/bin/activate'
allow 'source ~/.bashrc'
allow 'curl -sS https://api.example.com/health'
allow 'curl -v https://example.com'
allow 'echo "$GH_TOKEN_FILE_PATH_NOT_SET" | wc -c'
allow 'echo "$DOCKER_TOKEN" | docker login -u me --password-stdin'
allow 'docker compose up -d'
allow 'docker compose config --services'
allow "docker inspect --format '{{.State.Status}}' api"
allow 'vercel env pull .env.local'
allow 'cat src/app.js'
allow 'echo $((1 + 2))'
allow 'python manage.py runserver'
allow 'GH_TOKEN=$(gh auth token) gh api user'
allow 'curl -sS -H "Authorization: Bearer $(gcloud auth print-access-token)" https://x'
allow 'gh auth status'
allow 'kubectl get secrets'
allow 'heroku config:set FOO=bar'
allow 'aws configure get region'
allow "node -e \"console.log(process.env.NODE_ENV)\""
allow "bash $S/run-secure.sh -- 'curl -v -H \"Authorization: Bearer \$API_KEY\" https://x'"
deny  "bash $S/run-secure.sh -- curl -sS -H \"Authorization: Bearer \$API_KEY\" https://x"
allow "bash $S/run-secure.sh -- bash -c 'cat .env | grep KEY'"
allow ".claude/skills/secure-env/scripts/list-env-keys.sh"
allow "bash .claude/skills/secure-env/scripts/redact.sh .env"
allow "bash .claude/skills/secure-env/scripts/env-set.sh API_KEY --generate"
allow "cd apps/api && bash ../../.claude/skills/secure-env/scripts/run-secure.sh -- npm test"

echo "== Hook: debe PREGUNTAR (archivo con un secreto adentro)"
ask 'cat logs/response.json'
ask 'tail -n 20 logs/response.json'
ask 'jq . < logs/response.json'

echo "== Hook: herramientas de archivo"
expect deny  Read file_path "$PROJ/.env"
expect deny  Read file_path "$PROJ/apps/api/.env.local"
expect allow Read file_path "$PROJ/.env.example"
expect allow Read file_path "$PROJ/src/app.js"
expect ask   Read file_path "$PROJ/logs/response.json"
expect deny  Read file_path "$HOME/.ssh/id_rsa"
expect deny  Edit file_path "$PROJ/.env"
expect deny  Write file_path "$PROJ/.env"
expect allow Write file_path "$PROJ/apps/web/.env"
expect allow Edit file_path "$PROJ/src/app.js"
expect deny  Grep path "$PROJ/.env"
expect deny  Grep glob ".env*"
expect allow Grep path "$PROJ/src"

echo "== run-secure: redacción"
cd "$PROJ" || exit 1
out="$(bash "$S/run-secure.sh" -- 'echo "k=$API_KEY"; echo "t=$HUBSPOT_TOKEN" >&2; echo "port=$PORT"' 2>&1)"
case "$out" in *"$SECRET_KEY"*|*"$HUB_TOKEN"*) bad "run-secure dejó pasar un secreto" "$out" ;; *) ok ;; esac
case "$out" in *"[REDACTED:API_KEY]"*) ok ;; *) bad "no aparece [REDACTED:API_KEY]" "$out" ;; esac
case "$out" in *"port=3000"*) ok ;; *) bad "PORT (pública) no debería redactarse" "$out" ;; esac

out="$(bash "$S/run-secure.sh" -- bash -c 'printf "%s" "$N8N_WEBHOOK_URL" | sed "s#/#\\\\/#g"; echo; printf "%s:" "$API_KEY" | base64; python3 -c "import urllib.parse,os;print(urllib.parse.quote(os.environ[\"DATABASE_URL\"],safe=\"\"))" 2>/dev/null || true')"
case "$out" in *7f3c2a91*|*"$(printf '%s:' "$SECRET_KEY" | base64 | tr -d '=\n')"*) bad "variantes JSON/base64 sin redactar" "$out" ;; *) ok ;; esac
case "$out" in *"S3cr3t"*) bad "password dentro de DATABASE_URL sin redactar" "$out" ;; *) ok ;; esac
out="$(bash "$S/run-secure.sh" -- bash -c 'echo "base postgres en $LOCAL_DATABASE_URL y auth en $BETTER_AUTH_URL"')"
case "$out" in "base postgres en [REDACTED:LOCAL_DATABASE_URL] y auth en http://localhost:3000") ok ;; *) bad "clave trivial de URL u origen solo redactados (o URL completa sin redactar)" "$out" ;; esac

out="$(bash "$S/run-secure.sh" -- bash -c 'printf "%s\n" "$PRIVATE_KEY"')"
case "$out" in *MIIEvQIBADANBgkqhkiG9w0BAQEFAASC*) bad "llave privada multilínea sin redactar" "$out" ;; *) ok ;; esac

out="$(bash "$S/run-secure.sh" -- bash -c 'echo "$AWS_REGION $API_BASE_URL $CONTACT_EMAIL"')"
case "$out" in *"us-east-1 https://api.hubapi.com ops@example.com"*) ok ;; *) bad "valores no sensibles fueron redactados (fricción)" "$out" ;; esac

out="$(bash "$S/run-secure.sh" -- bash -c 'echo "$STRIPE_SECRET"' )"
[ -z "$out" ] && ok || bad "sin -f no debería cargar apps/api/.env.local" "$out"
out="$(cd apps/api && bash "$S/run-secure.sh" -- bash -c 'echo "$STRIPE_SECRET"')"
case "$out" in "[REDACTED:STRIPE_SECRET]") ok ;; *) bad "debería cargar .env.local de la carpeta actual y redactar" "$out" ;; esac

out="$(GITHUB_TOKEN=ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8 bash "$S/run-secure.sh" -- bash -c 'echo $GITHUB_TOKEN')"
case "$out" in "[REDACTED:GITHUB_TOKEN]") ok ;; *) bad "variable sensible heredada sin redactar" "$out" ;; esac
out="$(CLAUDE_CODE_SESSION_ID=0f8e2c1a-5b7d-4e3f-9a6c-2d1b8e7f4a90 CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-a1B2c3D4e5F6g7H8i9J0 bash "$S/run-secure.sh" -- bash -c 'echo $CLAUDE_CODE_SESSION_ID $CLAUDE_CODE_OAUTH_TOKEN')"
case "$out" in "0f8e2c1a-5b7d-4e3f-9a6c-2d1b8e7f4a90 [REDACTED:CLAUDE_CODE_OAUTH_TOKEN]") ok ;; *) bad "id de sesión de Claude Code redactado (no es secreto) o token OAuth sin redactar" "$out" ;; esac

bash "$S/run-secure.sh" -- bash -c 'exit 7'; [ $? -eq 7 ] && ok || bad "no propaga el código de salida"
out="$(echo entrada-ok | bash "$S/run-secure.sh" -- cat)"; [ "$out" = "entrada-ok" ] && ok || bad "stdin no llega al comando" "$out"

echo "== PostToolUse: red de seguridad"
post() { printf '{"cwd":"%s","hook_event_name":"PostToolUse","tool_name":"%s","tool_input":{"command":"x"},"tool_response":%s}' "$(jesc "$PROJ")" "$1" "$2" | bash "$S/posttool-redact.sh"; }
out="$(post Bash "{\"stdout\":\"config={\\\"key\\\":\\\"$SECRET_KEY\\\"} hook=$WEBHOOK\",\"stderr\":\"\",\"interrupted\":false,\"isImage\":false}")"
case "$out" in *"$SECRET_KEY"*|*7f3c2a91*) bad "PostToolUse dejó pasar un secreto" "$out" ;; *) ok ;; esac
case "$out" in *'"updatedToolOutput":{"stdout":"config={\"key\":\"[REDACTED:API_KEY]\"}'*'"interrupted":false,"isImage":false}'*) ok ;; *) bad "PostToolUse no conservó la forma del objeto Bash" "$out" ;; esac
if command -v python3 >/dev/null 2>&1; then
  printf '%s' "$out" | python3 -c 'import json,sys; json.load(sys.stdin)' 2>/dev/null && ok || bad "PostToolUse emitió JSON inválido" "$out"
fi
out="$(post Bash '{"stdout":"todo bien","stderr":"","interrupted":false,"isImage":false}')"
[ -z "$out" ] && ok || bad "PostToolUse no debería tocar salidas sin secretos" "$out"
out="$(post mcp__hubspot__get "[{\"type\":\"text\",\"text\":\"token $HUB_TOKEN\"}]")"
case "$out" in *'"updatedToolOutput":[{"type":"text","text":"token [REDACTED:HUBSPOT_TOKEN]"}]'*) ok ;; *) bad "PostToolUse no redactó la salida de un MCP" "$out" ;; esac
out="$(post Read "{\"type\":\"text\",\"file\":{\"filePath\":\"x\",\"content\":\"pk=$(printf '%s' "$SECRET_KEY" | base64 | tr -d '=\n')\"}}")"
case "$out" in *"[REDACTED:API_KEY]"*) ok ;; *) bad "PostToolUse no redactó la variante base64" "$out" ;; esac

echo "== list-env-keys / redact / env-set"
out="$(bash "$S/list-env-keys.sh")"
case "$out" in *"$SECRET_KEY"*|*"$HUB_TOKEN"*|*S3cr3t*) bad "list-env-keys muestra un secreto" "$out" ;; *) ok ;; esac
case "$out" in *"PORT"*"3000"*"(pública)"*) ok ;; *) bad "list-env-keys no muestra PORT" "$out" ;; esac
out="$(bash "$S/redact.sh" .env)"
case "$out" in *"$SECRET_KEY"*|*"$HUB_TOKEN"*) bad "redact.sh .env muestra un secreto" "$out" ;; *) ok ;; esac
case "$out" in *"API_KEY=[REDACTED:API_KEY]"*) ok ;; *) bad "redact.sh no redacta como se espera" "$out" ;; esac

out="$(bash "$S/env-set.sh" NEW_TOKEN 'valor con espacios #1')"
case "$out" in *"valor con espacios"*) bad "env-set imprimió el valor" "$out" ;; *) ok ;; esac
grep -q "^NEW_TOKEN='valor con espacios #1'$" .env && ok || bad "env-set no escribió la línea esperada" "$(tail -2 .env)"
bash "$S/env-set.sh" PORT 4000 >/dev/null && grep -q '^PORT=4000$' .env && ! grep -q '^PORT=3000$' .env && ok || bad "env-set no actualizó PORT"
grep -q '^# credenciales$' .env && ok || bad "env-set borró comentarios"
bash "$S/env-set.sh" PRIVATE_KEY --unset >/dev/null && ! grep -q 'PRIVATE KEY' .env && grep -q '^NEW_TOKEN=' .env && ok || bad "env-set --unset con valor multilínea"
out="$(bash "$S/env-set.sh" -f apps/api/.env.local JWT_SECRET --generate 16)"
grep -Eq '^JWT_SECRET=[0-9a-f]{32}$' apps/api/.env.local && ok || bad "env-set --generate" "$out"
bash "$S/env-set.sh" -f nuevo/.env X 1 >/dev/null 2>&1; [ ! -e nuevo/.env ] && ok || bad "env-set creó un directorio inexistente"
bash "$S/env-set.sh" -f .env.nuevo FOO bar >/dev/null && perm="$(ls -l .env.nuevo | cut -c1-10)" && [ "$perm" = "-rw-------" ] && ok || bad "archivo nuevo sin permisos 600" "${perm:-}"

echo
echo "Resultado: $pass OK, $fail fallas"
[ $fail -eq 0 ]

# secure-env

Evita que los valores de `.env` (API keys, tokens, contraseñas, URLs de webhooks) terminen en el contexto de un agente de código, sin frenar su trabajo normal. Viene listo para Claude Code; para otros agentes, ver [Otros agentes](#otros-agentes).

## Instalación (2 minutos)

1. Desde la raíz de tu proyecto:
   ```bash
   git clone --depth 1 https://github.com/cristobalhiza/secure-env-skill .claude/skills/secure-env
   rm -rf .claude/skills/secure-env/.git
   ```
   La carpeta tiene que llamarse `secure-env`: el guardia reconoce sus propios scripts por esa ruta.
2. Desde la raíz del proyecto:
   ```bash
   bash .claude/skills/secure-env/install.sh
   ```
   Fusiona permisos y hooks en `.claude/settings.json` (respaldo en `settings.json.bak`), completa `.gitignore`, avisa si hay algún `.env` ya versionado y corre las 185 pruebas.
3. Reinicia Claude Code.
4. Versiona `.claude/` para que todo el equipo quede protegido al hacer `git pull`.

Requisitos: bash y awk, que vienen en macOS, Linux, WSL y Git for Windows (Claude Code en Windows ya usa Git Bash). `install.sh` usa python3 o node solo para fusionar el JSON; si no hay ninguno, te dice qué pegar a mano (`settings.example.json`).

## Cómo funciona

| Capa | Qué hace | Si falla |
|---|---|---|
| Permisos `deny` | Claude Code no deja leer los `.env` comunes ni llaves SSH/AWS con sus herramientas ni con `cat`/`head`/`<` | Nativo de Claude Code |
| Hook **PreToolUse** (`pretool-guard.sh`) | Antes de ejecutar, analiza el comando (incluye `$(...)`, pipes, heredocs y `bash -c`) y bloquea lo que imprimiría un secreto, con un mensaje que dice qué usar en su lugar | Deja pasar y avisa (no traba el trabajo); siguen activos los `deny` y el PostToolUse |
| Hook **PostToolUse** (`posttool-redact.sh`) | Después de cualquier herramienta (Bash, Read, Grep, MCP…), reemplaza cada secreto en la salida por `[REDACTED:NOMBRE]` antes de que Claude la vea | Red de seguridad para lo imprevisto: un script propio que loguea su config, una API que repite el token |
| `run-secure.sh` | Carga el `.env`, ejecuta y redacta stdout/stderr. Dentro de él todo está permitido | — |
| `SKILL.md` | Enseña al agente a usar las herramientas y a escribir código que no loguee credenciales | — |

**Qué se considera secreto.** Todo valor de cualquier `.env` del proyecto (`.env`, `.env.local`, `.env.production`, `apps/api/.env`, `config/prod.env`, `.envrc`, `.dev.vars`), más variables sensibles del entorno del sistema (ej. `GITHUB_TOKEN`). Excepciones para no generar fricción:

- Nombres públicos: `PORT`, `NODE_ENV`, `NEXT_PUBLIC_*`, `VITE_*`… (`SECURE_ENV_PUBLIC_VARS`).
- Nombres neutros (`AWS_REGION`, `DB_HOST`, `API_BASE_URL`) con valores que no parecen secretos: hosts, emails, rutas, URLs sin credenciales.
- Valores muy cortos o triviales (`true`, `3000`, `dev`).

Los nombres con KEY, TOKEN, SECRET, PASS, AUTH, WEBHOOK, PRIVATE, DSN, COOKIE, SESSION… siempre son secretos. Las URLs con usuario:clave o con un token en la ruta (webhooks de n8n/Make/Slack) también. La redacción cubre el valor literal, escapado en JSON, URL-encoded y en base64 (headers Basic), cada línea de llaves PEM multilínea y la contraseña dentro de `DATABASE_URL`.

## Qué bloquea y qué deja pasar (ejemplos de las pruebas)

**Bloquea** (con mensaje de alternativa): `cat .env`, `grep KEY .env`, `source .env && node app.js`, `node --env-file=.env`, `docker run --env-file .env`, `env`, `printenv`, `export -p`, `echo $API_KEY`, `curl -H "Authorization: Bearer $TOKEN"` fuera del wrapper, `set -x`, `bash -x`, `curl -v --netrc`, `node -e "console.log(process.env)"`, `python -c "print(os.environ['X'])"`, `echo $(cat .env)`, `cp .env /tmp/x`, `git diff .env`, `git add .env`, `docker compose config`, `docker inspect` sin `--format`, `cat ~/.ssh/id_ed25519`, comandos que imprimen credenciales de un gestor (`gh auth token`, `gcloud auth print-access-token`, `security find-generic-password -w`, `op read`, `kubectl get secret -o yaml`, `heroku config`), leer o editar `.env` con Read/Edit/Grep.

**Deja pasar**: `npm run dev`, `node app.js`, `git status`, `cp .env.example .env`, `echo ".env" >> .gitignore`, `test -f .env`, `chmod 600 .env`, `mv .env .env.bak`, `cat .env.example`, `echo $HOME`, `echo ${#API_KEY}`, `test -n "$API_KEY"`, `echo "$TOKEN" | docker login --password-stdin`, `GH_TOKEN=$(gh auth token) gh api user`, `docker compose up -d`, `vercel env pull`, `grep -rn "process.env" src/`, `source .venv/bin/activate`, y todo lo que vaya dentro de `run-secure.sh`. Para escribir en un `.env`, el camino es `env-set.sh`: las reglas `deny` de Claude Code también frenan Edit/Write sobre esos archivos.

**Pregunta al usuario** si un archivo que Claude va a leer (Read, `cat`, `tail`, `jq`…) contiene el valor de un secreto: un log, una respuesta guardada, una credencial hardcodeada.

## Uso diario

```bash
S=.claude/skills/secure-env/scripts
bash $S/list-env-keys.sh                       # qué variables hay, sin valores secretos
bash $S/redact.sh logs/app.log                 # leer algo con los secretos tapados
bash $S/run-secure.sh -- 'curl -sS -H "Authorization: Bearer $HUBSPOT_TOKEN" https://api.hubapi.com/...'
bash $S/run-secure.sh -f .env.production -- node scripts/sync.js
bash $S/env-set.sh STRIPE_KEY 'sk_live_...'    # agrega/actualiza sin mostrar el valor
bash $S/env-set.sh JWT_SECRET --generate 32
```

## Configuración

Edita `config.sh` (lo comparte el equipo) o crea `config.local.sh` al lado (personal, ignorado por git):

| Variable | Para qué |
|---|---|
| `SECURE_ENV_PUBLIC_VARS` | Variables que nunca se redactan |
| `SECURE_ENV_SECRET_VARS` | Variables que siempre se redactan, aunque parezcan inocentes (ej. `HUBSPOT_PORTAL_ID`) |
| `SECURE_ENV_STRICT=1` | Redactar todo valor no público, sin heurística |
| `SECURE_ENV_REDACT_NUMERIC=1` | Redactar también IDs numéricos |
| `SECURE_ENV_EXTRA_FILES` | `.env` fuera del proyecto (ej. `~/.secrets/clientes.env`) |
| `SECURE_ENV_SECRET_FILES` | Archivos de credenciales que no se leen (llaves, `.netrc`, cuentas de servicio) |
| `SECURE_ENV_ALLOW_COMMANDS` | Comandos que pueden mencionar `.env` sin wrapper (regex, uno por línea) |
| `SECURE_ENV_READ_CHECK=0` | Desactivar la pregunta al leer archivos que contienen secretos |

## Verificar que funciona (en Claude Code)

1. `bash .claude/skills/secure-env/scripts/env-set.sh CANARY_TOKEN --generate 16`
2. Pídele a Claude: *"ejecuta `bash .claude/skills/secure-env/tests/canary.sh` y dime qué imprimió"*. Debe responder `[REDACTED:CANARY_TOKEN]`. Si ve 32 caracteres hex, el PostToolUse no está activo (revisa `/hooks`).
3. Pídele: *"muéstrame el contenido del .env"*. Debe bloquearse y ofrecerte `list-env-keys` o `redact.sh`.
4. Borra el canario: `bash .claude/skills/secure-env/scripts/env-set.sh CANARY_TOKEN --unset`.

Repite el paso 2 cuando actualices Claude Code: la redacción del PostToolUse depende de que Claude Code acepte la salida reescrita. Si cambia su formato y la rechaza, el PreToolUse y los `deny` siguen protegiendo, pero conviene saberlo.

## Límites (léelos)

- **Protege contra accidentes, no contra un agente decidido a filtrar.** Un comando ofuscado a propósito (partir el valor, invertirlo, cifrarlo) puede pasar. Lo que sí frena son los errores reales: un `cat .env` para "revisar", un `console.log(config)`, un `curl -v`, un `set -x`, un error de Axios volcado entero.
- **El contexto no es el único lugar sensible.** Los valores siguen en el `.env` en disco; esto no reemplaza un gestor de secretos (1Password `op run`, Doppler, Infisical) ni la rotación de credenciales.
- **Lo que el usuario pega en el chat ya está en el contexto.** Usa `env-set.sh` para guardarlo y no lo repitas.
- **Valores cortos** (menos de 6 caracteres) no se redactan, para no tapar texto común. Usa contraseñas largas.
- El análisis de comandos es de bash; los comandos de PowerShell se revisan en lo básico (`Get-Content .env`, `Get-ChildItem env:`, `$env:SECRETO`).

## Licencia

MIT. Ver [LICENSE](LICENSE).

## Pruebas

```bash
bash .claude/skills/secure-env/tests/run-tests.sh
```

185 casos (bloqueos, permisos, redacción en todas sus variantes, PostToolUse, scripts). Verificado con gawk, mawk y el awk BSD de macOS.

## Otros agentes

El motor y las herramientas (`run-secure`, `redact`, `list-env-keys`, `env-set`) son bash y awk, sin nada de Claude Code. Lo único específico es el JSON de los hooks. En otro agente (Codex, Cursor, Gemini CLI…), pídele que lea [`ADAPTERS.md`](ADAPTERS.md): ahí está el contrato de los hooks, cómo escribir un adaptador corto sin tocar el motor y la verificación que tiene que pasar antes de darlo por instalado.

La protección completa depende de que ese agente tenga un hook posterior capaz de reemplazar la salida de una herramienta. Si no lo tiene, quedan el bloqueo previo, `run-secure` y las reglas: cubren los descuidos comunes, pero no un script que imprima secretos por su cuenta.

## Estructura

```
secure-env/
├── SKILL.md                 instrucciones para el agente
├── README.md                este archivo
├── ADAPTERS.md              cómo conectarla a otro agente
├── LICENSE                  MIT
├── config.sh                configuración del equipo
├── install.sh               instalación idempotente
├── settings.example.json    permisos y hooks (por si los copias a mano)
├── scripts/
│   ├── run-secure.sh        ejecutar con .env cargado y salida redactada
│   ├── list-env-keys.sh     listar variables sin valores
│   ├── redact.sh            leer archivos/stdin con secretos tapados
│   ├── env-set.sh           escribir en .env sin mostrar valores
│   ├── pretool-guard.sh     hook PreToolUse
│   ├── posttool-redact.sh   hook PostToolUse
│   └── lib/                 motor (awk portable, sin dependencias)
└── tests/
    ├── run-tests.sh
    └── canary.sh
```

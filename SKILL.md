---
name: secure-env
description: >-
  Protege los secretos de un proyecto mientras el agente trabaja: evita que valores de .env, API keys,
  tokens, contraseñas y URLs de webhooks entren al contexto o a los registros de sesión, y da herramientas
  para usarlos sin verlos (run-secure, list-env-keys, redact, env-set). Úsala siempre que la tarea toque
  archivos .env o variables de entorno, credenciales, llamadas curl o scripts autenticados, conexiones a
  bases de datos, docker o ssh con configuración sensible, depuración de configuración, o revisar si un
  secreto quedó expuesto; también cuando un hook de secure-env bloquee un comando, aparezca
  [REDACTED:NOMBRE] en una salida, o haya que instalarla o adaptarla a otro agente. Basta con que el
  trabajo necesite una credencial, aunque nadie diga "secreto" ni "seguridad". In English: use it for any
  task involving .env files, environment variables, API keys, tokens, passwords, webhook URLs,
  database URLs or authenticated scripts.
license: MIT
compatibility: bash y awk (macOS, Linux, WSL, Git Bash). Hooks listos para Claude Code; otros agentes vía ADAPTERS.md.
---

# secure-env

Lo que una herramienta imprime entra a tu contexto y queda guardado en los registros de sesión, en texto plano y en disco. Un `cat .env` para "revisar" basta para que una API key quede ahí para siempre. Esta skill evita eso con tres capas:

1. **Hook PreToolUse**: antes de ejecutar, bloquea lo que imprimiría un secreto (leer un `.env`, volcar el entorno, usar `$SECRETO` fuera del wrapper, `set -x`, `curl -v` con credenciales…). Su mensaje dice qué usar en su lugar.
2. **Hook PostToolUse**: revisa la salida de cualquier herramienta y reemplaza cada valor secreto por `[REDACTED:NOMBRE]` antes de que lo veas, también en el registro de la sesión.
3. **Esta guía**: cómo trabajar con credenciales sin necesitar ver sus valores.

Las rutas de abajo son relativas a la raíz del proyecto; si estás en una subcarpeta, ajústalas (ej. `../../.claude/...`). Si no estás en Claude Code, lee primero [la última sección](#si-no-estás-en-claude-code).

## Herramientas

| Necesito… | Uso |
|---|---|
| Saber qué variables hay | `bash .claude/skills/secure-env/scripts/list-env-keys.sh` (nombres y largo; valores solo de las públicas) |
| Ver un .env o un log sin exponer secretos | `bash .claude/skills/secure-env/scripts/redact.sh <archivo>` |
| Ejecutar algo que usa credenciales | `bash .claude/skills/secure-env/scripts/run-secure.sh -- '<línea de shell>'` |
| Saber si un secreto aparece en algún archivo, sin verlo | `run-secure` con un comando que solo cuente (ejemplo abajo) |
| Agregar/cambiar/borrar una variable | `bash .claude/skills/secure-env/scripts/env-set.sh [-f archivo] CLAVE VALOR` · `CLAVE --generate [bytes]` · `CLAVE --unset` |

Para buscar un valor sin verlo, compáralo dentro de `run-secure` e imprime solo conteos:

```bash
bash .claude/skills/secure-env/scripts/run-secure.sh -- 'grep -rlF "$API_KEY" logs/ | wc -l'
```

## Ejecutar con credenciales: run-secure

`run-secure` carga `./.env` y `./.env.local` (o los de la raíz), ejecuta el comando y redacta stdout y stderr. Adentro puedes usar `-v`, `set -x` o imprimir lo que quieras: la salida se limpia. Devuelve el código de salida del comando.

Pasa la línea completa como **un solo argumento entre comillas simples**, para que `$VARIABLE` se expanda adentro, con el .env ya cargado, y no en tu shell, donde estaría vacía:

```bash
bash .claude/skills/secure-env/scripts/run-secure.sh -- 'curl -sS -H "Authorization: Bearer $HUBSPOT_TOKEN" "https://api.hubapi.com/crm/v3/objects/contacts?limit=1"'
bash .claude/skills/secure-env/scripts/run-secure.sh -- 'curl -sS -X POST "$WEBHOOK_URL" -H "Content-Type: application/json" -d @payload.json'
bash .claude/skills/secure-env/scripts/run-secure.sh -- node scripts/sync.js
bash .claude/skills/secure-env/scripts/run-secure.sh -f .env.production -- npm run migrate
```

Lo que no usa secretos (`npm run dev`, `git status`, `ls`) se ejecuta normal, sin wrapper.

## Reglas

- **No leas un `.env`** con Read, cat, grep, sed, python, node ni nada: sus valores quedarían en el contexto y en el registro. Para nombres, `list-env-keys`; para el contenido, `redact.sh`.
- **No escribas un valor secreto literal** en un comando, archivo de código, commit o respuesta. Referéncialo por nombre (`$API_KEY`, `process.env.API_KEY`); el valor vive solo en el `.env`.
- **Si ves `[REDACTED:NOMBRE]`**, el sistema funciona. No intentes recuperar el valor. Para confirmar que una credencial es válida, haz una llamada real dentro de `run-secure` y mira el status HTTP.
- **Si el usuario te pega un secreto en el chat**, guárdalo con `env-set.sh` y no lo repitas en tus respuestas: cada repetición es otra copia en el registro.
- **Para crear un `.env` nuevo**: `cp .env.example .env` y luego `env-set.sh` por cada valor. No lo edites con Edit/Write, que mostrarían su contenido.
- **No agregues `.env` a git.** Si `git status` muestra un `.env`, avísale al usuario.
- **Si una salida muestra un secreto de todos modos** (un valor que no estaba en ningún `.env`, un token que devolvió una API), dile al usuario qué fue y dónde quedó, sin repetirlo, para que decida si rotarlo.

## Cuando el guardia bloquea algo

Primero distingue qué pasó:

- **Bloqueo real**: el comando habría mostrado un valor (lee el `.env`, imprime una variable, hace un `grep -r` que entra al `.env`). Usa la alternativa que da el mensaje. No lo rodees para conseguir el valor por otro camino (copiar el archivo, codificarlo en base64, partirlo, leerlo desde otro intérprete): el bloqueo protege al usuario, no es un error a esquivar.
- **Falso positivo**: el comando solo *menciona* un `.env` como texto y no lee nada; por ejemplo, un mensaje de commit o una descripción que dice ".env". Reformular está bien: pasa el texto desde un archivo (`git commit -F mensaje.txt`) o escríbelo de otra forma ("archivo de entorno"). Si se repite, cuéntaselo al usuario.
- **Algo legítimo que necesita pasar**: explícale al usuario qué intentabas y qué bloqueó el hook, sin el valor. Él puede permitir el comando en `SECURE_ENV_ALLOW_COMMANDS` o marcar una variable como pública en `SECURE_ENV_PUBLIC_VARS`, ambos en `.claude/skills/secure-env/config.sh`.

## Escribir código que no filtre secretos

Al crear o modificar scripts que usan credenciales:

- No loguees objetos de configuración, headers, `process.env`/`os.environ`, ni el objeto de error completo de un cliente HTTP: Axios (`err.config.headers`), `requests` (`e.request.headers`), Guzzle y fetch incluyen la Authorization o la URL con token.
- Loguea solo lo útil:

```js
// Node / Axios
catch (err) {
  console.error('HubSpot falló:', err.response?.status, err.code, err.response?.data?.message);
}
```

```python
# Python / requests
except requests.HTTPError as e:
    print("HubSpot falló:", e.response.status_code, e.response.text[:300])
```

```php
// PHP / Guzzle
catch (\GuzzleHttp\Exception\RequestException $e) {
    error_log('Falló: ' . ($e->hasResponse() ? $e->getResponse()->getStatusCode() : $e->getMessage()));
}
```

- Para verificar que una variable cargó, muestra presencia y largo, nunca un fragmento:
  `console.log('API_KEY', process.env.API_KEY ? `[SET len=${process.env.API_KEY.length}]` : '[FALTA]')`
- Las URLs de webhooks son credenciales: quien tiene la URL dispara el flujo. Trátalas igual que una API key.

## Si no estás en Claude Code

Los hooks vienen en el formato de Claude Code. Si eres otro agente (Codex, Cursor, Gemini CLI…) o la skill está en otra carpeta (ej. `.agents/skills/secure-env/`; la carpeta tiene que llamarse `secure-env`), las herramientas y las reglas valen igual, ajustando las rutas. Las capas 1 y 2, en cambio, no están activas hasta que escribas tu adaptador:

1. Lee `ADAPTERS.md` (al lado de este archivo) y sigue sus pasos.
2. No des la instalación por terminada sin pasar su verificación (bloqueo de `.env` y canario): un adaptador mal hecho no da error, deja todo pasar.
3. Dile al usuario qué capas quedaron activas y cuáles no existen en tu entorno.

Mientras tanto, usa `run-secure` para todo lo que toque credenciales: redacta su propia salida en cualquier agente.

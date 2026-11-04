---
name: secure-env
description: Trabajar con secretos sin exponerlos en el chat. Úsalo siempre que una tarea toque archivos .env o variables de entorno, API keys, tokens, contraseñas, URLs de webhooks (n8n, Make, Clay, Slack), llamadas curl o scripts autenticados, depuración de configuración, o cuando un hook de secure-env bloquee un comando o aparezca [REDACTED:...] en una salida.
---

# secure-env

Este proyecto protege sus secretos con tres capas. Las dos primeras son automáticas (hooks); esta guía es la tercera: cómo trabajar con credenciales sin que sus valores lleguen nunca al contexto.

1. **Hook PreToolUse** bloquea, antes de ejecutar, lo que imprimiría un secreto: leer un `.env`, volcar el entorno, usar `$SECRETO` fuera del wrapper, `set -x`, `curl -v` con credenciales, etc. Su mensaje dice exactamente qué usar en su lugar.
2. **Hook PostToolUse** revisa la salida de cualquier herramienta y reemplaza cualquier valor secreto por `[REDACTED:NOMBRE]` antes de que lo veas.
3. **Estas reglas.**

Las rutas de abajo son relativas a la raíz del proyecto; si estás en una subcarpeta, ajústalas (ej. `../../.claude/...`).

## Si no estás en Claude Code

Los hooks vienen en el formato de Claude Code. Si eres otro agente (Codex, Cursor, Gemini CLI…) o la skill está en otra carpeta (ej. `.agents/skills/`), las herramientas y estas reglas valen igual (ajusta las rutas), pero las capas 1 y 2 no están activas hasta que escribas tu adaptador:

1. Lee `ADAPTERS.md` (al lado de este archivo) y sigue sus pasos.
2. No des la instalación por terminada sin pasar su verificación (bloqueo de `.env` y canario). Un adaptador mal hecho no da error: deja todo pasar.
3. Dile al usuario qué capas quedaron activas y cuáles no existen en tu entorno.

Mientras tanto, usa `run-secure` para todo lo que toque credenciales: redacta su propia salida en cualquier agente.

## Herramientas

| Necesito… | Uso |
|---|---|
| Saber qué variables hay | `bash .claude/skills/secure-env/scripts/list-env-keys.sh` (nombres, largo; valores solo de las públicas) |
| Ver un .env o un log sin exponer secretos | `bash .claude/skills/secure-env/scripts/redact.sh <archivo>` |
| Ejecutar algo que usa credenciales | `bash .claude/skills/secure-env/scripts/run-secure.sh -- '<línea de shell>'` |
| Agregar/cambiar/borrar una variable | `bash .claude/skills/secure-env/scripts/env-set.sh [-f archivo] CLAVE VALOR` · `CLAVE --generate [bytes]` · `CLAVE --unset` |

## Ejecutar con credenciales: run-secure

`run-secure` carga `./.env` y `./.env.local` (o los de la raíz), ejecuta el comando y redacta stdout y stderr. Dentro de él puedes usar `-v`, `set -x` o imprimir lo que quieras: la salida se limpia.

Pasa la línea completa como **un solo argumento entre comillas simples**, para que `$VARIABLE` se expanda adentro (con el .env ya cargado) y no en tu shell, donde estaría vacía:

```bash
bash .claude/skills/secure-env/scripts/run-secure.sh -- 'curl -sS -H "Authorization: Bearer $HUBSPOT_TOKEN" "https://api.hubapi.com/crm/v3/objects/contacts?limit=1"'
bash .claude/skills/secure-env/scripts/run-secure.sh -- 'curl -sS -X POST "$N8N_WEBHOOK_URL" -H "Content-Type: application/json" -d @payload.json'
bash .claude/skills/secure-env/scripts/run-secure.sh -- node scripts/sync.js
bash .claude/skills/secure-env/scripts/run-secure.sh -f .env.production -- npm run migrate
bash .claude/skills/secure-env/scripts/run-secure.sh -- docker compose up -d
```

Comandos que no usan secretos (`npm run dev`, `git status`, `ls`) se ejecutan normal, sin wrapper.

## Reglas

- **Nunca leas un `.env`** con Read, cat, grep, sed, python, node ni nada. Para nombres: `list-env-keys`. Para contenido: `redact.sh`.
- **Nunca escribas un valor secreto literal** en un comando, archivo de código, commit o respuesta. Referéncialo por nombre (`$API_KEY`, `process.env.API_KEY`).
- **Si un hook bloquea algo**, usa la alternativa que indica el mensaje. No lo rodees (copiar el archivo, codificarlo en base64, partirlo, leerlo desde otro intérprete, etc.): el bloqueo existe para proteger al usuario, no es un error a esquivar.
- **Si ves `[REDACTED:NOMBRE]`**, el sistema funciona. No intentes recuperar el valor. Si necesitas confirmar que una credencial es válida, haz una llamada real dentro de `run-secure` y mira el status HTTP.
- **Si el usuario te pega un secreto en el chat**, guárdalo con `env-set.sh` y no lo repitas en tus respuestas.
- **Crear un `.env` nuevo**: `cp .env.example .env` y luego `env-set.sh` por cada valor. No edites `.env` con Edit/Write.
- **Nunca agregues `.env` a git.** Si `git status` muestra un `.env`, avisa al usuario.

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

## Si algo legítimo queda bloqueado

Explícale al usuario qué intentabas y qué bloqueó el hook (sin el valor). Él puede permitir ese comando agregándolo a `SECURE_ENV_ALLOW_COMMANDS` en `.claude/skills/secure-env/config.sh`, o marcar una variable como pública en `SECURE_ENV_PUBLIC_VARS`.

# Usar secure-env con otro agente

secure-env viene listo para Claude Code. El motor (`scripts/lib/*.awk`) y las herramientas (`run-secure`, `redact`, `list-env-keys`, `env-set`) no dependen del agente; lo único atado a Claude Code es el formato del JSON que entra y sale de los dos hooks.

Para otro agente (Codex, Cursor, Gemini CLI, etc.) no se cambia el motor: se escribe **un adaptador** que traduce el JSON de ese agente al de Claude Code, llama al hook existente y traduce la respuesta de vuelta. Esta guía es para el agente que hace la instalación.

> Los hooks corren sin el modelo. El adaptador se escribe **una vez**, al instalar, como un script; no se traduce nada "en vivo".

## 1. Qué ofrece tu entorno

Revisa la documentación de hooks de tu agente y responde:

| Capa | Pregunta | Si no existe |
|---|---|---|
| Antes de ejecutar | ¿Hay un hook que reciba el comando o la ruta **antes** de ejecutar y pueda **bloquearlo** (y, si se puede, pedir confirmación)? | Sin bloqueo previo. Quedan `run-secure` y las reglas de `SKILL.md`. |
| Después de ejecutar | ¿Hay un hook que reciba la salida de la herramienta y pueda **reemplazarla** antes de que el modelo la vea? | Sin red de seguridad: un script propio que imprima su config llega sin redactar. |
| Permisos | ¿Se pueden denegar lecturas de archivos por patrón (`.env`, `~/.ssh/*`)? | Solo protege el hook previo. |

No inventes capacidades: si la documentación no dice que la salida se puede reemplazar, asume que no.

## 2. El contrato de los hooks

Llama a los scripts existentes con `CLAUDE_PROJECT_DIR` apuntando a la raíz del proyecto (ahí se buscan los `.env`). Si no lo defines, usan `git rev-parse --show-toplevel` o el directorio actual.

### Antes de ejecutar: `scripts/pretool-guard.sh`

Entrada por stdin (forma de Claude Code):

```json
{ "tool_name": "Bash", "cwd": "/ruta/al/proyecto", "tool_input": { "command": "cat .env" } }
```

| Tu herramienta | `tool_name` | Campo en `tool_input` |
|---|---|---|
| Shell (bash, sh, zsh) | `Bash` | `command` |
| PowerShell | `PowerShell` | `command` |
| Leer archivo | `Read` | `file_path` |
| Escribir o editar archivo | `Write` (o `Edit`) | `file_path` |
| Buscar en archivos | `Grep` | `path` y, si hay, `glob` |

Cualquier otra herramienta se permite; no hace falta pasarla.

Salida:

| Resultado | Significa | Qué debe hacer tu adaptador |
|---|---|---|
| exit 0, stdout vacío | Permitido | Permitir |
| exit 2, motivo en stderr | Bloqueado | Bloquear y mostrar el motivo al modelo: trae la alternativa a usar |
| exit 0, stdout con `{"hookSpecificOutput":{"permissionDecision":"ask","permissionDecisionReason":"…"}}` | Hay que preguntar al usuario | Pedir confirmación con ese motivo. Si tu agente no puede preguntar, **bloquear** |

Si el guardia no logra analizar la entrada, deja pasar y escribe `secure-env: el guardia no pudo analizar…` en stderr. Muéstralo: es la señal de que el adaptador manda algo mal.

### Después de ejecutar: `scripts/posttool-redact.sh`

Entrada por stdin:

```json
{ "tool_name": "Bash", "tool_response": { "stdout": "…", "stderr": "…" } }
```

`tool_response` puede ser un string, un objeto o un arreglo: pasa la salida de tu herramienta tal cual la recibes.

Salida:

| Resultado | Qué debe hacer tu adaptador |
|---|---|
| stdout vacío | No había secretos: dejar la salida original |
| stdout con `hookSpecificOutput.updatedToolOutput` | Reemplazar la salida por ese valor (misma forma que la que entraste). `additionalContext` es un aviso para el modelo y `systemMessage` uno para el usuario |

## 3. Dónde dejarlo

- La carpeta de la skill tiene que llamarse `secure-env` (ej. `.agents/skills/secure-env/`): el guardia reconoce `run-secure.sh` y los demás scripts por la ruta `secure-env/scripts/`. Con otro nombre, bloquea el propio wrapper.
- Adaptador en `adapters/<agente>/` (ej. `adapters/codex/pretool.sh`), lo más corto posible: traducir, llamar al hook, traducir de vuelta.
- Configura los hooks del agente para que lo llamen. **Muéstrale al usuario la configuración antes de guardarla**: es un cambio de permisos.
- No modifiques `scripts/lib/` ni los hooks: así las 185 pruebas siguen valiendo.

## 4. Verificación obligatoria

Un adaptador que lee mal un campo no da error: el motor recibe un comando vacío, permite todo y la protección no existe. No des la instalación por terminada sin estas pruebas **dentro del agente**, con tus propias herramientas:

1. `bash tests/run-tests.sh` → `0 fallas` (el motor funciona en esta máquina).
2. Intenta leer `.env` con la herramienta de leer archivos y con `cat .env` → ambos deben bloquearse con un mensaje de secure-env.
3. `bash scripts/env-set.sh CANARY_TOKEN --generate 16` y luego `bash tests/canary.sh` → debes ver `[REDACTED:CANARY_TOKEN]`, no 32 caracteres hex.
4. Si tu agente guarda registros de sesión, confirma sin imprimirlo que el valor del canario no quedó ahí:
   `bash scripts/run-secure.sh -- 'grep -rlF "$CANARY_TOKEN" <carpeta de registros> | wc -l'` → `0`.
5. `bash scripts/env-set.sh CANARY_TOKEN --unset`.

## 5. Informe al usuario

Al terminar, dile en pocas líneas:

- Qué capas quedaron activas (antes, después, permisos) y cuáles no existen en este agente.
- El resultado de cada prueba del paso 4.
- Si falta la capa "después": que la protección cubre los descuidos comunes (`cat .env`, `echo $TOKEN`, `curl -v`), pero no un script que imprima secretos por su cuenta, y que para esos casos use `run-secure`.

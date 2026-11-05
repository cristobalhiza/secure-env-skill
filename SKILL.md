---
name: secure-env
description: >-
  Use when a task needs real credentials without exposing them: .env values, API keys, tokens,
  passwords, webhook or database URLs. Covers saving, pasting or rotating a key or token someone gave
  you (e.g. into .env.production), running curl or authenticated scripts, connecting services (db,
  docker, ssh), debugging 401/403 errors or variables that don't load, auditing whether a secret
  leaked, and when a secure-env hook blocks a command, [REDACTED:NAME] shows up, or the skill must be
  installed or adapted to another agent. Provides run-secure, list-env-keys, redact and env-set to
  work with secrets without seeing them. Applies whenever the work needs a credential, even if nobody
  says "secret". Not for tasks that only write files without sensitive values (.gitignore or
  .env.example with sample values, docs, tests, builds). En español: úsala para tareas con
  credenciales reales, guardar en el .env una API key que te pasaron, o llamadas autenticadas.
license: MIT
compatibility: bash and awk (macOS, Linux, WSL, Git Bash). Hooks ready for Claude Code; other agents via ADAPTERS.md.
---

# secure-env

Whatever a tool prints enters your context and is stored in the session logs, in plain text, on disk. A single `cat .env` to "take a look" is enough for an API key to stay there forever. This skill prevents that with three layers:

1. **PreToolUse hook**: before running, it blocks anything that would print a secret (reading a `.env`, dumping the environment, using `$SECRET` outside the wrapper, `set -x`, `curl -v` with credentials…). Its message says what to use instead.
2. **PostToolUse hook**: it scans the output of every tool and replaces each secret value with `[REDACTED:NAME]` before you see it, in the session log too.
3. **This guide**: how to work with credentials without needing to see their values.

The paths below are relative to the project root; if you are in a subfolder, adjust them (e.g. `../../.claude/...`). If you are not in Claude Code, read [the last section](#if-you-are-not-in-claude-code) first.

## Tools

| I need to… | Use |
|---|---|
| Know which variables exist | `bash .claude/skills/secure-env/scripts/list-env-keys.sh` (names and length; values only for public ones) |
| Look at a .env or a log without exposing secrets | `bash .claude/skills/secure-env/scripts/redact.sh <file>` |
| Run something that uses credentials | `bash .claude/skills/secure-env/scripts/run-secure.sh -- '<shell line>'` |
| Know whether a secret appears in some file, without seeing it | `run-secure` with a command that only counts (example below) |
| Add/change/delete a variable | `bash .claude/skills/secure-env/scripts/env-set.sh [-f file] KEY VALUE` · `KEY --generate [bytes]` · `KEY --unset` |

To search for a value without seeing it, compare it inside `run-secure` and print only counts:

```bash
bash .claude/skills/secure-env/scripts/run-secure.sh -- 'grep -rlF "$API_KEY" logs/ | wc -l'
```

## Running with credentials: run-secure

`run-secure` loads `./.env` and `./.env.local` (or the ones at the root), runs the command and redacts stdout and stderr. Inside it you can use `-v`, `set -x` or print whatever you want: the output gets cleaned. It returns the command's exit code.

Pass the whole line as **a single argument in single quotes**, so `$VARIABLE` expands inside, with the .env already loaded, and not in your shell, where it would be empty:

```bash
bash .claude/skills/secure-env/scripts/run-secure.sh -- 'curl -sS -H "Authorization: Bearer $HUBSPOT_TOKEN" "https://api.hubapi.com/crm/v3/objects/contacts?limit=1"'
bash .claude/skills/secure-env/scripts/run-secure.sh -- 'curl -sS -X POST "$WEBHOOK_URL" -H "Content-Type: application/json" -d @payload.json'
bash .claude/skills/secure-env/scripts/run-secure.sh -- node scripts/sync.js
bash .claude/skills/secure-env/scripts/run-secure.sh -f .env.production -- npm run migrate
```

Anything that doesn't use secrets (`npm run dev`, `git status`, `ls`) runs normally, without the wrapper.

## Rules

- **Don't read a `.env`** with Read, cat, grep, sed, python, node or anything else: its values would end up in the context and the log. For names, `list-env-keys`; for the content, `redact.sh`.
- **Don't write a literal secret value** in a command, code file, commit or reply. Reference it by name (`$API_KEY`, `process.env.API_KEY`); the value lives only in the `.env`.
- **If you see `[REDACTED:NAME]`**, the system is working. Don't try to recover the value. To confirm a credential is valid, make a real call inside `run-secure` and check the HTTP status.
- **If the user pastes a secret in the chat**, save it with `env-set.sh` and don't repeat it in your replies: each repetition is another copy in the log.
- **To create a new `.env`**: `cp .env.example .env` and then `env-set.sh` for each value. Don't edit it with Edit/Write, which would show its content.
- **Don't add `.env` to git.** If `git status` shows a `.env`, tell the user.
- **If some output shows a secret anyway** (a value that wasn't in any `.env`, a token returned by an API), tell the user what it was and where it ended up, without repeating it, so they can decide whether to rotate it.

## When the guard blocks something

First figure out what happened:

- **Real block**: the command would have shown a value (it reads the `.env`, prints a variable, runs a `grep -r` that enters the `.env`). Use the alternative the message gives. Don't work around it to get the value another way (copying the file, base64-encoding it, splitting it, reading it from another interpreter): the block protects the user, it isn't an error to dodge.
- **False positive**: the command only *mentions* a `.env` as text and reads nothing; for example, a commit message or a description that says ".env". Rephrasing is fine: pass the text from a file (`git commit -F message.txt`) or write it another way ("environment file"). If it keeps happening, tell the user.
- **Something legitimate that needs to go through**: explain to the user what you were trying to do and what the hook blocked, without the value. They can allow the command in `SECURE_ENV_ALLOW_COMMANDS` or mark a variable as public in `SECURE_ENV_PUBLIC_VARS`, both in `.claude/skills/secure-env/config.sh`.

## Writing code that doesn't leak secrets

When creating or changing scripts that use credentials:

- Don't log config objects, headers, `process.env`/`os.environ`, or an HTTP client's full error object: Axios (`err.config.headers`), `requests` (`e.request.headers`), Guzzle and fetch include the Authorization header or the URL with the token.
- Log only what's useful:

```js
// Node / Axios
catch (err) {
  console.error('HubSpot failed:', err.response?.status, err.code, err.response?.data?.message);
}
```

```python
# Python / requests
except requests.HTTPError as e:
    print("HubSpot failed:", e.response.status_code, e.response.text[:300])
```

```php
// PHP / Guzzle
catch (\GuzzleHttp\Exception\RequestException $e) {
    error_log('Failed: ' . ($e->hasResponse() ? $e->getResponse()->getStatusCode() : $e->getMessage()));
}
```

- To check that a variable loaded, show presence and length, never a fragment:
  `console.log('API_KEY', process.env.API_KEY ? `[SET len=${process.env.API_KEY.length}]` : '[MISSING]')`
- Webhook URLs are credentials: whoever has the URL can trigger the flow. Treat them like an API key.

## If you are not in Claude Code

The hooks come in Claude Code's format. If you are another agent (Codex, Cursor, Gemini CLI…) or the skill lives in another folder (e.g. `.agents/skills/secure-env/`; the folder must be named `secure-env`), the tools and rules still apply, with adjusted paths. Layers 1 and 2, however, aren't active until you write your adapter:

1. Read `ADAPTERS.md` (next to this file) and follow its steps.
2. Don't consider the installation done until it passes its verification (`.env` block and canary): a broken adapter doesn't raise an error, it lets everything through.
3. Tell the user which layers are active and which don't exist in your environment.

In the meantime, use `run-secure` for everything that touches credentials: it redacts its own output in any agent.

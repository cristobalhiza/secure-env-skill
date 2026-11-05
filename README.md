# secure-env

Keeps `.env` values (API keys, tokens, passwords, webhook URLs) out of a coding agent's context, without slowing down its normal work. Ready for Claude Code; for other agents, see [Other agents](#other-agents).

## Installation (2 minutes)

1. From your project root:
   ```bash
   git clone --depth 1 https://github.com/cristobalhiza/secure-env-skill .claude/skills/secure-env
   rm -rf .claude/skills/secure-env/.git
   ```
   The folder must be named `secure-env`: the guard recognizes its own scripts by that path.
2. From the project root:
   ```bash
   bash .claude/skills/secure-env/install.sh
   ```
   It merges permissions and hooks into `.claude/settings.json` (backup in `settings.json.bak`), completes `.gitignore`, warns if any `.env` is already tracked, and runs the 185 tests.
3. Restart Claude Code.
4. Commit `.claude/` so the whole team is protected after a `git pull`.

Requirements: bash and awk, which ship with macOS, Linux, WSL and Git for Windows (Claude Code on Windows already uses Git Bash). `install.sh` uses python3 or node only to merge the JSON; if neither is available, it tells you what to paste by hand (`settings.example.json`).

## How it works

| Layer | What it does | If it fails |
|---|---|---|
| `deny` permissions | Claude Code won't read common `.env` files or SSH/AWS keys with its tools or with `cat`/`head`/`<` | Native to Claude Code |
| **PreToolUse** hook (`pretool-guard.sh`) | Before running, it parses the command (including `$(...)`, pipes, heredocs and `bash -c`) and blocks anything that would print a secret, with a message saying what to use instead | Lets it through and warns (doesn't block work); the `deny` rules and PostToolUse stay active |
| **PostToolUse** hook (`posttool-redact.sh`) | After any tool (Bash, Read, Grep, MCP…), replaces every secret in the output with `[REDACTED:NAME]` before Claude sees it | Safety net for the unexpected: your own script logging its config, an API echoing the token |
| `run-secure.sh` | Loads the `.env`, runs and redacts stdout/stderr. Anything goes inside it | — |
| `SKILL.md` | Teaches the agent to use the tools and to write code that doesn't log credentials | — |

**What counts as a secret.** Every value in any `.env` in the project (`.env`, `.env.local`, `.env.production`, `apps/api/.env`, `config/prod.env`, `.envrc`, `.dev.vars`), plus sensitive variables from the system environment (e.g. `GITHUB_TOKEN`). Exceptions, to avoid friction:

- Public names: `PORT`, `NODE_ENV`, `NEXT_PUBLIC_*`, `VITE_*`… (`SECURE_ENV_PUBLIC_VARS`).
- Neutral names (`AWS_REGION`, `DB_HOST`, `API_BASE_URL`) with values that don't look secret: hosts, emails, paths, URLs without credentials.
- Very short or trivial values (`true`, `3000`, `dev`).

Names containing KEY, TOKEN, SECRET, PASS, AUTH, WEBHOOK, PRIVATE, DSN, COOKIE, SESSION… are always secrets. So are URLs with user:password or a token in the path (n8n/Make/Slack webhooks). Redaction covers the literal value, JSON-escaped, URL-encoded and base64 (Basic headers), every line of multi-line PEM keys, and the password inside `DATABASE_URL`.

## What it blocks and what it allows (examples from the tests)

**Blocks** (with an alternative in the message): `cat .env`, `grep KEY .env`, `source .env && node app.js`, `node --env-file=.env`, `docker run --env-file .env`, `env`, `printenv`, `export -p`, `echo $API_KEY`, `curl -H "Authorization: Bearer $TOKEN"` outside the wrapper, `set -x`, `bash -x`, `curl -v --netrc`, `node -e "console.log(process.env)"`, `python -c "print(os.environ['X'])"`, `echo $(cat .env)`, `cp .env /tmp/x`, `git diff .env`, `git add .env`, `docker compose config`, `docker inspect` without `--format`, `cat ~/.ssh/id_ed25519`, commands that print credentials from a manager (`gh auth token`, `gcloud auth print-access-token`, `security find-generic-password -w`, `op read`, `kubectl get secret -o yaml`, `heroku config`), reading or editing `.env` with Read/Edit/Grep.

**Allows**: `npm run dev`, `node app.js`, `git status`, `cp .env.example .env`, `echo ".env" >> .gitignore`, `test -f .env`, `chmod 600 .env`, `mv .env .env.bak`, `cat .env.example`, `echo $HOME`, `echo ${#API_KEY}`, `test -n "$API_KEY"`, `echo "$TOKEN" | docker login --password-stdin`, `GH_TOKEN=$(gh auth token) gh api user`, `docker compose up -d`, `vercel env pull`, `grep -rn "process.env" src/`, `source .venv/bin/activate`, and anything inside `run-secure.sh`. To write to a `.env`, the way is `env-set.sh`: Claude Code's `deny` rules also stop Edit/Write on those files.

**Asks the user** when a file Claude is about to read (Read, `cat`, `tail`, `jq`…) contains a secret value: a log, a saved response, a hardcoded credential.

## Daily use

```bash
S=.claude/skills/secure-env/scripts
bash $S/list-env-keys.sh                       # which variables exist, without secret values
bash $S/redact.sh logs/app.log                 # read something with secrets masked
bash $S/run-secure.sh -- 'curl -sS -H "Authorization: Bearer $HUBSPOT_TOKEN" https://api.hubapi.com/...'
bash $S/run-secure.sh -f .env.production -- node scripts/sync.js
bash $S/env-set.sh STRIPE_KEY 'sk_live_...'    # add/update without showing the value
bash $S/env-set.sh JWT_SECRET --generate 32
```

## Configuration

Edit `config.sh` (shared by the team) or create `config.local.sh` next to it (personal, ignored by git):

| Variable | Purpose |
|---|---|
| `SECURE_ENV_PUBLIC_VARS` | Variables that are never redacted |
| `SECURE_ENV_SECRET_VARS` | Variables that are always redacted, even if they look harmless (e.g. `HUBSPOT_PORTAL_ID`) |
| `SECURE_ENV_STRICT=1` | Redact every non-public value, no heuristics |
| `SECURE_ENV_REDACT_NUMERIC=1` | Redact numeric IDs too |
| `SECURE_ENV_EXTRA_FILES` | `.env` files outside the project (e.g. `~/.secrets/clients.env`) |
| `SECURE_ENV_SECRET_FILES` | Credential files that are never read (keys, `.netrc`, service accounts) |
| `SECURE_ENV_ALLOW_COMMANDS` | Commands allowed to mention `.env` without the wrapper (regex, one per line) |
| `SECURE_ENV_READ_CHECK=0` | Turn off the prompt when reading files that contain secrets |

## Check that it works (in Claude Code)

1. `bash .claude/skills/secure-env/scripts/env-set.sh CANARY_TOKEN --generate 16`
2. Ask Claude: *"run `bash .claude/skills/secure-env/tests/canary.sh` and tell me what it printed"*. It should answer `[REDACTED:CANARY_TOKEN]`. If it sees 32 hex characters, PostToolUse isn't active (check `/hooks`).
3. Ask it: *"show me the contents of the .env"*. It should be blocked and offer `list-env-keys` or `redact.sh`.
4. Delete the canary: `bash .claude/skills/secure-env/scripts/env-set.sh CANARY_TOKEN --unset`.

Repeat step 2 whenever you update Claude Code: PostToolUse redaction depends on Claude Code accepting the rewritten output. If its format changes and it rejects it, PreToolUse and the `deny` rules still protect you, but you'll want to know.

## Limits (read them)

- **It protects against accidents, not against an agent set on leaking.** A deliberately obfuscated command (splitting the value, reversing it, encrypting it) can get through. What it does stop are the real mistakes: a `cat .env` to "take a look", a `console.log(config)`, a `curl -v`, a `set -x`, a whole Axios error dumped.
- **The context isn't the only sensitive place.** The values are still in the `.env` on disk; this doesn't replace a secrets manager (1Password `op run`, Doppler, Infisical) or credential rotation.
- **Whatever the user pastes in the chat is already in the context.** Use `env-set.sh` to save it and don't repeat it.
- **Short values** (under 6 characters) aren't redacted, to avoid masking common text. Use long passwords.
- Command parsing is bash-based; PowerShell commands get only basic checks (`Get-Content .env`, `Get-ChildItem env:`, `$env:SECRET`).

## License

MIT. See [LICENSE](LICENSE).

## Tests

```bash
bash .claude/skills/secure-env/tests/run-tests.sh
```

185 cases (blocks, permissions, redaction in all its variants, PostToolUse, scripts). Verified with gawk, mawk and macOS's BSD awk.

## Other agents

The engine and the tools (`run-secure`, `redact`, `list-env-keys`, `env-set`) are bash and awk, with nothing Claude Code–specific. The only specific part is the hooks' JSON. In another agent (Codex, Cursor, Gemini CLI, Antigravity…), install it with git, from the project root:

```bash
git clone --depth 1 https://github.com/cristobalhiza/secure-env-skill .agents/skills/secure-env
rm -rf .agents/skills/secure-env/.git
```

Use your agent's skills folder if it isn't `.agents/skills/`, but keep the folder name `secure-env`. Then ask the agent to read [`ADAPTERS.md`](ADAPTERS.md): it has the hook contract, how to write a short adapter without touching the engine, and the verification it must pass before calling it installed.

**Copy, don't rewrite.** The files must arrive with `git clone` or `cp`, as they are. An agent that recreates them by writing their content takes minutes, spends a lot of tokens, and can introduce changes the tests won't catch. The only file the agent should write is its own adapter.

Full protection depends on that agent having a post-tool hook able to replace a tool's output. If it doesn't, you still get the pre-run block, `run-secure` and the rules: they cover the common slips, but not a script that prints secrets on its own.

## Layout

```
secure-env/
├── SKILL.md                 instructions for the agent
├── README.md                this file
├── ADAPTERS.md              how to hook it into another agent
├── LICENSE                  MIT
├── config.sh                team configuration
├── install.sh               idempotent installer
├── settings.example.json    permissions and hooks (if you copy them by hand)
├── scripts/
│   ├── run-secure.sh        run with .env loaded and output redacted
│   ├── list-env-keys.sh     list variables without values
│   ├── redact.sh            read files/stdin with secrets masked
│   ├── env-set.sh           write to .env without showing values
│   ├── pretool-guard.sh     PreToolUse hook
│   ├── posttool-redact.sh   PostToolUse hook
│   └── lib/                 engine (portable awk, no dependencies)
└── tests/
    ├── run-tests.sh
    └── canary.sh
```

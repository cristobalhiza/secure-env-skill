# Using secure-env with another agent

secure-env comes ready for Claude Code. The engine (`scripts/lib/*.awk`) and the tools (`run-secure`, `redact`, `list-env-keys`, `env-set`) don't depend on the agent; the only part tied to Claude Code is the format of the JSON going into and out of the two hooks.

For another agent (Codex, Cursor, Gemini CLI, etc.) the engine stays untouched: you write **an adapter** that translates that agent's JSON into Claude Code's, calls the existing hook and translates the response back. This guide is for the agent doing the installation.

> Hooks run without the model. The adapter is written **once**, at install time, as a script; nothing is translated "live".

## 0. Get the files (copy, don't rewrite)

From the project root, with a shell command:

```bash
git clone --depth 1 https://github.com/cristobalhiza/secure-env-skill .agents/skills/secure-env
rm -rf .agents/skills/secure-env/.git
```

If the skill is already in another project, `cp -r <that project>/.agents/skills/secure-env .agents/skills/`. Use your agent's skills folder if it isn't `.agents/skills/`; the folder must be named `secure-env`.

**Never recreate these files by writing their content** with your file-writing tool, not even "to adapt them": it's slow, costly, and a single changed character in `scripts/lib/` can open a hole the tests don't cover. Nothing in the skill needs changes for your agent. The only file you write is the adapter (step 3). If you can't run `git` or `cp`, stop and ask the user to copy the folder.

## 1. What your environment offers

Check your agent's hook documentation and answer:

| Layer | Question | If it doesn't exist |
|---|---|---|
| Before running | Is there a hook that receives the command or path **before** it runs and can **block** it (and, if possible, ask for confirmation)? | No pre-run block. You still have `run-secure` and the rules in `SKILL.md`. |
| After running | Is there a hook that receives the tool output and can **replace** it before the model sees it? | No safety net: your own script printing its config arrives unredacted. |
| Permissions | Can file reads be denied by pattern (`.env`, `~/.ssh/*`)? | Only the pre-run hook protects. |

Don't invent capabilities: if the documentation doesn't say the output can be replaced, assume it can't.

## 2. The hook contract

Call the existing scripts with `CLAUDE_PROJECT_DIR` pointing at the project root (that's where `.env` files are looked up). If you don't set it, they use `git rev-parse --show-toplevel` or the current directory.

### Before running: `scripts/pretool-guard.sh`

Input on stdin (Claude Code's shape):

```json
{ "tool_name": "Bash", "cwd": "/path/to/project", "tool_input": { "command": "cat .env" } }
```

| Your tool | `tool_name` | Field in `tool_input` |
|---|---|---|
| Shell (bash, sh, zsh) | `Bash` | `command` |
| PowerShell | `PowerShell` | `command` |
| Read file | `Read` | `file_path` |
| Write or edit file | `Write` (or `Edit`) | `file_path` |
| Search files | `Grep` | `path` and, if present, `glob` |

Any other tool is allowed; there's no need to pass it.

Output:

| Result | Meaning | What your adapter must do |
|---|---|---|
| exit 0, empty stdout | Allowed | Allow |
| exit 2, reason on stderr | Blocked | Block and show the reason to the model: it includes the alternative to use |
| exit 0, stdout with `{"hookSpecificOutput":{"permissionDecision":"ask","permissionDecisionReason":"…"}}` | The user must be asked | Ask for confirmation with that reason. If your agent can't ask, **block** |

If the guard can't parse the input, it lets it through and writes `secure-env: the guard could not parse…` to stderr. Show it: it's the sign that the adapter is sending something wrong.

### After running: `scripts/posttool-redact.sh`

Input on stdin:

```json
{ "tool_name": "Bash", "tool_response": { "stdout": "…", "stderr": "…" } }
```

`tool_response` can be a string, an object or an array: pass your tool's output exactly as you receive it.

Output:

| Result | What your adapter must do |
|---|---|
| empty stdout | There were no secrets: keep the original output |
| stdout with `hookSpecificOutput.updatedToolOutput` | Replace the output with that value (same shape as what you sent in). `additionalContext` is a notice for the model and `systemMessage` one for the user |

## 3. Where to put it

- The skill folder must be named `secure-env` (e.g. `.agents/skills/secure-env/`): the guard recognizes `run-secure.sh` and the other scripts by the path `secure-env/scripts/`. With another name, it blocks its own wrapper.
- Adapter in `adapters/<agent>/` (e.g. `adapters/codex/pretool.sh`), as short as possible: translate, call the hook, translate back.
- Configure the agent's hooks to call it. **Show the user the configuration before saving it**: it's a permissions change.
- Don't modify `scripts/lib/` or the hooks: that way the 185 tests stay valid.

## 4. Required verification

An adapter that reads a field wrong doesn't raise an error: the engine gets an empty command, allows everything, and the protection doesn't exist. Don't consider the installation done without these tests **inside the agent**, with your own tools:

1. `bash tests/run-tests.sh` → `0 failures` (the engine works on this machine).
2. Try to read `.env` with the read-file tool and with `cat .env` → both must be blocked with a secure-env message.
3. `bash scripts/env-set.sh CANARY_TOKEN --generate 16` and then `bash tests/canary.sh` → you must see `[REDACTED:CANARY_TOKEN]`, not 32 hex characters.
4. If your agent keeps session logs, confirm without printing it that the canary value didn't end up there:
   `bash scripts/run-secure.sh -- 'grep -rlF "$CANARY_TOKEN" <logs folder> | wc -l'` → `0`.
5. `bash scripts/env-set.sh CANARY_TOKEN --unset`.

## 5. Report to the user

When done, tell them in a few lines:

- Which layers are active (before, after, permissions) and which don't exist in this agent.
- The result of each test in step 4.
- If the "after" layer is missing: that the protection covers the common slips (`cat .env`, `echo $TOKEN`, `curl -v`), but not a script that prints secrets on its own, and that `run-secure` should be used for those cases.

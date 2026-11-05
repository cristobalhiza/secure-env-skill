#!/usr/bin/env bash
# install — enables secure-env in this project. It's idempotent: you can run it again.
#
#   bash .claude/skills/secure-env/install.sh            # install
#   bash .claude/skills/secure-env/install.sh --check    # only show what's missing
#
# It does three things:
#   1. Merges the "deny" permissions and both hooks (PreToolUse and PostToolUse) into
#      .claude/settings.json, without deleting what you already have. Backup in settings.json.bak.
#   2. Adds the missing .env entries (and config.local.sh) to .gitignore.
#   3. Runs the test suite.
set -u

SKILL="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLAUDE_DIR="$(dirname "$(dirname "$SKILL")")"     # .claude
ROOT="$(dirname "$CLAUDE_DIR")"
SETTINGS="$CLAUDE_DIR/settings.json"
EXAMPLE="$SKILL/settings.example.json"
CHECK=0; [ "${1:-}" = "--check" ] && CHECK=1

say() { printf '%s\n' "$*"; }

if [ "$(basename "$CLAUDE_DIR")" != ".claude" ]; then
  say "This skill must live in <project>/.claude/skills/secure-env (it's in $SKILL)."; exit 1
fi

# ---------------------------------------------------------------- 1. settings.json
merge_py='
import json, os, sys
settings, example, check = sys.argv[1], sys.argv[2], sys.argv[3] == "1"
cur = {}
if os.path.exists(settings):
    with open(settings, encoding="utf-8") as f:
        txt = f.read().strip()
        cur = json.loads(txt) if txt else {}
with open(example, encoding="utf-8") as f:
    ex = json.load(f)
changes = []
deny = cur.setdefault("permissions", {}).setdefault("deny", [])
for rule in ex["permissions"]["deny"]:
    if rule not in deny:
        deny.append(rule); changes.append("deny " + rule)
hooks = cur.setdefault("hooks", {})
for event, entries in ex["hooks"].items():
    lst = hooks.setdefault(event, [])
    for entry in entries:
        marker = entry["hooks"][0]["command"].split("/")[-1].strip("\"")
        present = any(marker in h.get("command", "") for e in lst for h in e.get("hooks", []))
        if not present:
            lst.append(entry); changes.append("hook " + event)
if check:
    print("\n".join(changes) if changes else "OK")
    sys.exit(0)
if changes:
    if os.path.exists(settings):
        os.replace(settings, settings + ".bak")
    with open(settings, "w", encoding="utf-8") as f:
        json.dump(cur, f, indent=2, ensure_ascii=False); f.write("\n")
print("\n".join(changes) if changes else "OK")
'

merge_js='
const fs = require("fs");
const [settings, example, check] = process.argv.slice(1);
let cur = {};
if (fs.existsSync(settings)) { const t = fs.readFileSync(settings, "utf8").trim(); cur = t ? JSON.parse(t) : {}; }
const ex = JSON.parse(fs.readFileSync(example, "utf8"));
const changes = [];
cur.permissions = cur.permissions || {}; cur.permissions.deny = cur.permissions.deny || [];
for (const r of ex.permissions.deny) if (!cur.permissions.deny.includes(r)) { cur.permissions.deny.push(r); changes.push("deny " + r); }
cur.hooks = cur.hooks || {};
for (const [ev, entries] of Object.entries(ex.hooks)) {
  cur.hooks[ev] = cur.hooks[ev] || [];
  for (const e of entries) {
    const marker = e.hooks[0].command.split("/").pop().replace(/"/g, "");
    const present = cur.hooks[ev].some(x => (x.hooks || []).some(h => (h.command || "").includes(marker)));
    if (!present) { cur.hooks[ev].push(e); changes.push("hook " + ev); }
  }
}
if (check !== "1" && changes.length) {
  if (fs.existsSync(settings)) fs.renameSync(settings, settings + ".bak");
  fs.writeFileSync(settings, JSON.stringify(cur, null, 2) + "\n");
}
console.log(changes.length ? changes.join("\n") : "OK");
'

say "== 1/3 .claude/settings.json"
if command -v python3 >/dev/null 2>&1 && python3 -c 'import json' 2>/dev/null; then
  res="$(python3 -c "$merge_py" "$SETTINGS" "$EXAMPLE" "$CHECK" 2>&1)"; rc=$?
elif command -v node >/dev/null 2>&1; then
  res="$(node -e "$merge_js" "$SETTINGS" "$EXAMPLE" "$CHECK" 2>&1)"; rc=$?
else
  rc=127
fi
if [ $rc -eq 127 ]; then
  say "   Couldn't find python3 or node to merge the JSON."
  say "   Copy the content of $EXAMPLE into $SETTINGS by hand."
elif [ $rc -ne 0 ]; then
  say "   Couldn't read $SETTINGS (invalid JSON?):"; say "   $res"; exit 1
elif [ "$res" = "OK" ]; then
  say "   Already configured."
else
  if [ $CHECK = 1 ]; then say "   Missing:"; else say "   Added (backup in settings.json.bak if it existed):"; fi
  printf '%s\n' "$res" | sed 's/^/     - /'
fi

# ---------------------------------------------------------------- 2. .gitignore
say "== 2/3 .gitignore"
GI="$ROOT/.gitignore"
want=".env
.env.*
!.env.example
!.env.sample
!.env.template
.dev.vars
.claude/skills/secure-env/config.local.sh"
added=""
while IFS= read -r line; do
  [ -n "$line" ] || continue
  if [ -f "$GI" ] && grep -qxF -- "$line" "$GI"; then continue; fi
  case "$line" in
    .env|.env.*|.dev.vars)
      if command -v git >/dev/null 2>&1 && git -C "$ROOT" check-ignore -q --no-index -- "$line" 2>/dev/null; then continue; fi ;;
  esac
  added="$added$line
"
done <<EOF
$want
EOF
if [ -z "$added" ]; then say "   Already covered."
elif [ $CHECK = 1 ]; then say "   Missing:"; printf '%s' "$added" | sed 's/^/     - /'
else
  { [ -f "$GI" ] && [ -n "$(tail -c1 "$GI")" ] && echo; echo "# secure-env"; printf '%s' "$added"; } >> "$GI"
  say "   Added:"; printf '%s' "$added" | sed 's/^/     - /'
fi
if command -v git >/dev/null 2>&1 && git -C "$ROOT" rev-parse >/dev/null 2>&1; then
  tracked="$(git -C "$ROOT" ls-files -- '.env' '*.env' '.env.*' '**/.env' '**/.env.*' 2>/dev/null | grep -Ev '\.(example|sample|template)$' || true)"
  if [ -n "$tracked" ]; then
    say "   WARNING: these files are already tracked in git and .gitignore won't remove them:"
    printf '%s\n' "$tracked" | sed 's/^/     - /'
    say "   Remove them from the index with: git rm --cached <file>  (and rotate those credentials)."
  fi
fi

# ---------------------------------------------------------------- 3. tests
say "== 3/3 tests"
if [ $CHECK = 1 ]; then say "   (skipped with --check)"; exit 0; fi
if bash "$SKILL/tests/run-tests.sh" >/tmp/secure-env-tests.$$ 2>&1; then
  say "   $(tail -1 /tmp/secure-env-tests.$$)"
else
  cat /tmp/secure-env-tests.$$; rm -f /tmp/secure-env-tests.$$; exit 1
fi
rm -f /tmp/secure-env-tests.$$
say
say "Done. Restart Claude Code (or open /hooks) so it picks up the hooks."
say "Optional live test: see README.md, section 'Check that it works'."

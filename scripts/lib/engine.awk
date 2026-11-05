# secure-env — shared engine (POSIX awk: works with gawk, mawk and macOS's awk).
# ALWAYS invoke with LC_ALL=C (works on bytes).
#
# Modes (-v MODE=...):
#   redact  filters stdin/files and replaces each secret with [REDACTED:NAME]
#   check   prints "MATCH<TAB>file<TAB>NAME" if some file contains a secret
#   list    lists .env variables without showing secret values
#   export  emits NAME<TAB>escaped-value for bash to export
#   set     rewrites a .env adding/updating/removing a variable
#   hook    decides a Claude Code PreToolUse (JSON payload on stdin) — see guard.awk
#
# Inputs via ENVIRON (not -v, so awk doesn't reinterpret backslashes):
#   SE_ENVFILES  .env file paths separated by \036
#   SE_INHERIT   "0" to ignore sensitive variables inherited from the environment
#   SECURE_ENV_* configuration (see config.sh)

BEGIN {
  se_init()
  if (MODE == "redact")      { load_all(ENVIRON["SE_INHERIT"] != "0"); finalize() }
  else if (MODE == "check")  { load_all(ENVIRON["SE_INHERIT"] != "0"); finalize() }
  else if (MODE == "list")   { mode_list(); exit 0 }
  else if (MODE == "export") { mode_export(); exit 0 }
  else if (MODE == "set")    { exit mode_set() }
  else if (MODE == "hook" || MODE == "post") { }   # handled by guard.awk (loaded as a second -f)
  else { print "secure-env: MODE desconocido: " MODE > "/dev/stderr"; exit 2 }
}

MODE == "redact" { print redact_line($0); fflush(); next }
MODE == "check"  { if (check_line($0)) { print "MATCH\t" FILENAME "\t" MATCHKEY; exit 0 } }

# ------------------------------------------------------------------ init

function se_init(   i) {
  for (i = 1; i < 256; i++) ORD[sprintf("%c", i)] = i
  B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
  SEP = "\036"
  MINLEN = ENVIRON["SECURE_ENV_MIN_LEN"] + 0
  if (MINLEN < 3) MINLEN = 6
  STRICT = (ENVIRON["SECURE_ENV_STRICT"] == "1")
  REDNUM = (ENVIRON["SECURE_ENV_REDACT_NUMERIC"] == "1")
  PUBRE = globs_to_re(ENVIRON["SECURE_ENV_PUBLIC_VARS"])
  FORCERE = globs_to_re(ENVIRON["SECURE_ENV_SECRET_VARS"])
  SENSRE = "(KEY|TOKEN|SECRET|PASS|PWD|(^|_)PW($|_)|CREDENTIAL|AUTH([^O]|$)|PRIVATE|DSN|WEBHOOK|COOKIE|SESSION|SIGNATURE|SALT|BEARER|JWT|OTP|PIN($|_))"
  SENSEXCL = "^(PWD|OLDPWD|SSH_AUTH_SOCK|XAUTHORITY|GPG_AGENT_INFO|SESSION_MANAGER|DBUS_SESSION_BUS_ADDRESS|XDG_SESSION_[A-Z_]*|DESKTOP_SESSION|CLAUDE_CODE_SESSION_ID|[A-Z0-9_]*_PUBLIC_[A-Z0-9_]*|SECURE_ENV_[A-Z0-9_]*|SE_[A-Z0-9_]*|TOKENIZERS_PARALLELISM)$"
  NV = 0; NP = 0; NO = 0; MAXL = 0
}

# Turns "PORT NEXT_PUBLIC_* VITE_*" into a regex ^(PORT|NEXT_PUBLIC_.*|VITE_.*)$
function globs_to_re(s,   n, a, i, j, c, g, out, r) {
  n = split(s, a, /[ \t\n,]+/)
  out = ""
  for (i = 1; i <= n; i++) {
    g = a[i]; if (g == "") continue
    r = ""
    for (j = 1; j <= length(g); j++) {
      c = substr(g, j, 1)
      if (c == "*") r = r ".*"
      else if (c == "?") r = r "."
      else if (index("\\^$.|+()[]{}", c)) r = r "\\" c
      else r = r c
    }
    out = out (out == "" ? "" : "|") r
  }
  if (out == "") return "^\001$"
  return "^(" out ")$"
}

# ------------------------------------------------------------------ .env parser (dotenv semantics)

function parse_file(path,   line, first, k, rest, q, val, alt, body, done, i, c, n, more, rc) {
  first = 1
  while ((rc = (getline line < path)) > 0) {
    if (first) { sub(/^\357\273\277/, "", line); first = 0 }
    sub(/\r$/, "", line)
    sub(/^[ \t]+/, "", line)
    if (line == "" || substr(line, 1, 1) == "#") continue
    sub(/^export[ \t]+/, "", line)
    if (!match(line, /^[A-Za-z_][A-Za-z0-9_.-]*[ \t]*=/)) continue
    k = substr(line, 1, RLENGTH - 1); sub(/[ \t]+$/, "", k)
    rest = substr(line, RLENGTH + 1); sub(/^[ \t]+/, "", rest)
    q = substr(rest, 1, 1); alt = ""
    if (q == "\"" || q == "'" || q == "`") {
      body = substr(rest, 2); val = ""
      for (;;) {
        n = length(body); done = 0
        for (i = 1; i <= n; i++) {
          c = substr(body, i, 1)
          if (c == "\\" && q != "'" && i < n) { val = val c substr(body, i + 1, 1); i++; continue }
          if (c == q) { done = 1; break }
          val = val c
        }
        if (done) break
        if ((getline more < path) <= 0) break
        sub(/\r$/, "", more)
        val = val "\n"; body = more
      }
      if (q == "\"") val = unescape_dq(val)
    } else {
      val = rest
      if (match(val, /[ \t]#/)) val = substr(val, 1, RSTART - 1)
      sub(/[ \t]+$/, "", val)
      # dotenv (Node) cuts at the first '#' even without a space: we record it as an alternative
      if (index(val, "#") > 1) { alt = substr(val, 1, index(val, "#") - 1); sub(/[ \t]+$/, "", alt) }
    }
    NV++; VK[NV] = k; VV[NV] = val; VA[NV] = alt; VF[NV] = path
  }
  close(path)
  return rc
}

function unescape_dq(s,   out, i, n, c, d) {
  out = ""; n = length(s)
  for (i = 1; i <= n; i++) {
    c = substr(s, i, 1)
    if (c == "\\" && i < n) {
      d = substr(s, i + 1, 1)
      if (d == "n") { out = out "\n"; i++; continue }
      if (d == "r") { out = out "\r"; i++; continue }
    }
    out = out c
  }
  return out
}

# ------------------------------------------------------------------ classification

function name_is_public(k) { return (k ~ PUBRE) }

function name_is_sensitive(k,   u) {
  if (k ~ PUBRE) return 0
  if (k ~ FORCERE) return 1
  u = toupper(k)
  return (u ~ SENSRE && u !~ SENSEXCL)
}

# Should this value be treated as a secret?
function value_secret(k, v,   lv) {
  if (k ~ PUBRE) return 0
  if (length(v) < MINLEN) return 0
  lv = tolower(v)
  if (lv ~ /^(true|false|null|none|nil|yes|no|on|off|undefined|localhost|development|production|staging|test|debug|info|warn|warning|error)$/) return 0
  if (STRICT || k ~ FORCERE) return 1
  # A bare origin (http://localhost:3000, https://app.example.com) grants access to nothing,
  # even if the name says AUTH (BETTER_AUTH_URL, NEXTAUTH_URL).
  if (is_bare_origin(v)) return 0
  if (v ~ /^[0-9][0-9.,:_-]*$/ && !REDNUM && !name_is_sensitive(k)) return 0
  if (name_is_sensitive(k)) return 1
  # Neutral name (DB_HOST, AWS_REGION, API_BASE_URL...): the value's shape decides.
  if (v ~ /^[A-Za-z][A-Za-z0-9+.-]*:\/\//) return url_has_secret(v)
  if (v ~ /^[^@ \t]+@[^@ \t]+\.[A-Za-z][A-Za-z]+$/) return 0
  if (v ~ /^[A-Za-z0-9.-]+\.[A-Za-z][A-Za-z]+(:[0-9]+)?$/) return 0
  if (v ~ /^(\/|\.\/|\.\.\/|~\/|[A-Za-z]:\\)/) return 0
  return looks_random(v)
}

function looks_random(v) {
  if (v ~ /[ \t]/) return 0
  if (length(v) >= 24) return 1
  return (length(v) >= 16 && v ~ /[A-Za-z]/ && v ~ /[0-9]/)
}

# scheme://host[:port][/] with no user, path, query or token-shaped host labels.
function is_bare_origin(v,   hp, n, a, i) {
  if (v !~ /^[A-Za-z][A-Za-z0-9+.-]*:\/\/[^\/?#@ \t]+\/?$/) return 0
  hp = v; sub(/^[A-Za-z][A-Za-z0-9+.-]*:\/\//, "", hp); sub(/\/$/, "", hp); sub(/:[0-9]+$/, "", hp)
  n = split(hp, a, ".")
  for (i = 1; i <= n; i++) if (looks_random(a[i]) || (length(a[i]) >= 12 && a[i] ~ /[0-9]/ && a[i] ~ /[A-Za-z]/)) return 0
  return 1
}

# URL password that protects nothing: truly empty, a sample one, or equal to the user
# (postgres://postgres:postgres@127.0.0.1). Redacting it would mask the word everywhere.
function trivial_pw(pw, user,   l) {
  l = tolower(pw)
  return (pw == user || l ~ /^(postgres|postgresql|password|passw0rd|secret|admin|root|changeme|example|mysql|mariadb|redis|mongo|mongodb|user|test|dev|local|guest|default)$/)
}

function url_has_secret(v,   rest, hp, n, a, i) {
  rest = v; sub(/^[A-Za-z][A-Za-z0-9+.-]*:\/\//, "", rest)
  hp = rest; sub(/\/.*/, "", hp); sub(/\?.*/, "", hp)
  if (index(hp, "@")) return 1
  n = split(rest, a, /[\/?&=#]/)
  for (i = 2; i <= n; i++) if (looks_random(a[i]) || (length(a[i]) >= 16 && a[i] ~ /[0-9]/)) return 1
  return 0
}

# ------------------------------------------------------------------ redaction patterns

function load_all(inherit,   n, F, i, name) {
  n = split(ENVIRON["SE_ENVFILES"], F, SEP)
  for (i = 1; i <= n; i++) if (F[i] != "") parse_file(F[i])
  for (i = 1; i <= NV; i++) {
    if (value_secret(VK[i], VV[i])) { add_secret(VK[i], VV[i]); SECNAME[VK[i]] = 1 }
    if (VA[i] != "" && value_secret(VK[i], VA[i])) add_secret(VK[i], VA[i])
  }
  if (inherit) {
    for (name in ENVIRON) {
      if (name_is_sensitive(name) && value_secret(name, ENVIRON[name])) add_secret(name, ENVIRON[name])
    }
  }
}

function add_secret(k, v,   n, parts, j, p) {
  if (index(v, "\n")) {
    n = split(v, parts, "\n")
    for (j = 1; j <= n; j++) {
      p = parts[j]; sub(/\r$/, "", p); sub(/^[ \t]+/, "", p); sub(/[ \t]+$/, "", p)
      if (length(p) >= MINLEN && p !~ /^-----(BEGIN|END) /) add_variants(k, p, 0)
    }
    add_pat(k, json_esc(v, 1)); add_pat(k, json_esc(v, 0))
    return
  }
  add_variants(k, v, 1)
}

function add_variants(k, p, deep,   rest, hp, ui, pw, n, a, i) {
  add_pat(k, p)
  add_pat(k, json_esc(p, 1)); add_pat(k, json_esc(p, 0))
  add_pat(k, urlenc(p))
  add_pat(k, b64(p)); add_pat(k, b64(p ":")); add_pat(k, b64url(p))
  if (!deep || p !~ /^[A-Za-z][A-Za-z0-9+.-]*:\/\//) return
  rest = p; sub(/^[A-Za-z][A-Za-z0-9+.-]*:\/\//, "", rest)
  hp = rest; sub(/\/.*/, "", hp); sub(/\?.*/, "", hp)
  if (index(hp, "@")) {
    ui = hp; sub(/@[^@]*$/, "", ui)
    pw = index(ui, ":") ? substr(ui, index(ui, ":") + 1) : ""
    if (pw == "" || !trivial_pw(pw, substr(ui, 1, index(ui, ":") - 1))) {
      add_pat(k, ui); add_pat(k, b64(ui))
      if (length(pw) >= 4) add_variants(k, pw, 0)
    }
  }
  n = split(rest, a, /[\/?&=#]/)
  for (i = 2; i <= n; i++) if (looks_random(a[i]) || (length(a[i]) >= 16 && a[i] ~ /[0-9]/)) add_variants(k, a[i], 0)
}

function add_pat(k, p) {
  if (length(p) < 4 || (p in SEEN)) return
  SEEN[p] = 1; NP++; PK[NP] = k; PV[NP] = p
  if (length(p) > MAXL) MAXL = length(p)
}

# Sorts by length, longest first (bucket sort), so the longest pattern wins.
function finalize(   i, L, n, a, j) {
  for (i = 1; i <= NP; i++) { L = length(PV[i]); BKT[L] = BKT[L] " " i }
  NO = 0
  for (L = MAXL; L >= 1; L--) {
    if (!(L in BKT)) continue
    n = split(BKT[L], a, " ")
    for (j = 1; j <= n; j++) if (a[j] != "") { NO++; OI[NO] = a[j] + 0 }
  }
}

function redact_line(s,   j, i, t, tl, rep, res, pos) {
  for (j = 1; j <= NO; j++) {
    i = OI[j]; t = PV[i]
    if (index(s, t) == 0) continue
    rep = "[REDACTED:" PK[i] "]"; res = ""; tl = length(t)
    while ((pos = index(s, t)) > 0) { res = res substr(s, 1, pos - 1) rep; s = substr(s, pos + tl) }
    s = res s
  }
  return s
}

function check_line(s,   j, i) {
  for (j = 1; j <= NO; j++) { i = OI[j]; if (index(s, PV[i])) { MATCHKEY = PK[i]; return 1 } }
  return 0
}

# Returns the name of the variable whose value appears in the file, or "".
function scan_file(path, maxb,   line, bytes, rc, key) {
  if (NO == 0) return ""
  bytes = 0; key = ""
  while ((rc = (getline line < path)) > 0) {
    bytes += length(line) + 1
    if (check_line(line)) { key = MATCHKEY; break }
    if (maxb > 0 && bytes > maxb) break
  }
  close(path)
  return key
}

# ------------------------------------------------------------------ encodings

function json_esc(s, slash,   out, i, n, c) {
  out = ""; n = length(s)
  for (i = 1; i <= n; i++) {
    c = substr(s, i, 1)
    if (c == "\\") out = out "\\\\"
    else if (c == "\"") out = out "\\\""
    else if (c == "/" && slash) out = out "\\/"
    else if (c == "\n") out = out "\\n"
    else if (c == "\r") out = out "\\r"
    else if (c == "\t") out = out "\\t"
    else out = out c
  }
  return out
}

function urlenc(s,   out, i, n, c) {
  out = ""; n = length(s)
  for (i = 1; i <= n; i++) {
    c = substr(s, i, 1)
    if (c ~ /[A-Za-z0-9_.~-]/) out = out c
    else out = out sprintf("%%%02X", ORD[c])
  }
  return out
}

# base64 without padding (so it matches even if the original ends in '=')
function b64(s,   out, i, n, c1, c2, c3, t) {
  out = ""; n = length(s)
  for (i = 1; i <= n; i += 3) {
    c1 = ORD[substr(s, i, 1)] + 0
    c2 = (i + 1 <= n) ? ORD[substr(s, i + 1, 1)] + 0 : 0
    c3 = (i + 2 <= n) ? ORD[substr(s, i + 2, 1)] + 0 : 0
    t = c1 * 65536 + c2 * 256 + c3
    out = out substr(B64, int(t / 262144) % 64 + 1, 1) substr(B64, int(t / 4096) % 64 + 1, 1)
    if (i + 1 <= n) out = out substr(B64, int(t / 64) % 64 + 1, 1)
    if (i + 2 <= n) out = out substr(B64, t % 64 + 1, 1)
  }
  return out
}

function b64url(s,   t) { t = b64(s); gsub(/\+/, "-", t); gsub(/\//, "_", t); return t }

# Escapes \ , newline and tab to carry a value on a single line (bash decodes it with printf %b)
function line_esc(s,   out, i, n, c) {
  out = ""; n = length(s)
  for (i = 1; i <= n; i++) {
    c = substr(s, i, 1)
    if (c == "\\") out = out "\\\\"
    else if (c == "\n") out = out "\\n"
    else if (c == "\t") out = out "\\t"
    else if (c == "\r") out = out "\\r"
    else out = out c
  }
  return out
}

# ------------------------------------------------------------------ list mode

function mode_list(   n, F, i, j, cur, k, v, shown) {
  n = split(ENVIRON["SE_ENVFILES"], F, SEP)
  shown = 0
  for (i = 1; i <= n; i++) {
    if (F[i] == "") continue
    cur = NV
    if (parse_file(F[i]) < 0) { print "# " F[i] "  (could not be read)"; continue }
    shown++
    print "# " F[i]
    if (NV == cur) { print "  (no variables)"; continue }
    for (j = cur + 1; j <= NV; j++) {
      k = VK[j]; v = VV[j]
      if (v == "") printf "  %-32s [empty]\n", k
      else if (value_secret(k, v)) printf "  %-32s [secret, len=%d]\n", k, length(v)
      else if (name_is_sensitive(k)) printf "  %-32s [hidden: sensitive name but short or trivial value, len=%d — not redacted in outputs]\n", k, length(v)
      else if (index(v, "\n")) printf "  %-32s [multi-line, len=%d]\n", k, length(v)
      else printf "  %-32s = %s%s\n", k, v, (name_is_public(k) ? "   (public)" : "   (not sensitive)")
    }
  }
  if (shown == 0) print "No .env files found."
}

# ------------------------------------------------------------------ export mode

function mode_export(   n, F, i) {
  n = split(ENVIRON["SE_ENVFILES"], F, SEP)
  for (i = 1; i <= n; i++) if (F[i] != "") parse_file(F[i])
  for (i = 1; i <= NV; i++) {
    if (VK[i] !~ /^[A-Za-z_][A-Za-z0-9_]*$/) continue
    print VK[i] "\t" line_esc(VV[i])
  }
}

# ------------------------------------------------------------------ set mode

function fmt_val(v) {
  if (v ~ /^[A-Za-z0-9_.:\/@+=,~%-]*$/) return v
  if (index(v, "'") == 0 && index(v, "\n") == 0) return "'" v "'"
  return "\"" dq_esc(v) "\""
}

function dq_esc(s,   out, i, n, c) {
  out = ""; n = length(s)
  for (i = 1; i <= n; i++) {
    c = substr(s, i, 1)
    if (c == "\"") out = out "\\\""
    else if (c == "\n") out = out "\\n"
    else if (c == "\r") out = out "\\r"
    else out = out c
  }
  return out
}

# Does the line open a quote it doesn't close? (to skip multi-line values when replacing)
function opens_multiline(rest,   q, body, i, n, c) {
  q = substr(rest, 1, 1)
  if (q != "\"" && q != "'" && q != "`") return ""
  body = substr(rest, 2); n = length(body)
  for (i = 1; i <= n; i++) {
    c = substr(body, i, 1)
    if (c == "\\" && q != "'" && i < n) { i++; continue }
    if (c == q) return ""
  }
  return q
}

function closes_quote(line, q,   i, n, c) {
  n = length(line)
  for (i = 1; i <= n; i++) {
    c = substr(line, i, 1)
    if (c == "\\" && q != "'" && i < n) { i++; continue }
    if (c == q) return 1
  }
  return 0
}

function mode_set(   path, key, val, unset, line, t, k, rest, q, done, rc, out, n, haveNL) {
  path = ENVIRON["SE_SET_FILE"]; key = ENVIRON["SE_SET_KEY"]
  val = ENVIRON["SE_SET_VALUE"]; unset = (ENVIRON["SE_SET_UNSET"] == "1")
  done = 0; n = 0; haveNL = 1
  while ((rc = (getline line < path)) > 0) {
    t = line; sub(/\r$/, "", t); sub(/^[ \t]+/, "", t); sub(/^export[ \t]+/, "", t)
    if (match(t, /^[A-Za-z_][A-Za-z0-9_.-]*[ \t]*=/)) {
      k = substr(t, 1, RLENGTH - 1); sub(/[ \t]+$/, "", k)
      if (k == key) {
        rest = substr(t, RLENGTH + 1); sub(/^[ \t]+/, "", rest)
        q = opens_multiline(rest)
        if (q != "") while ((getline line < path) > 0) if (closes_quote(line, q)) break
        if (!unset && !done) { print key "=" fmt_val(val); n++ }
        done = 1
        continue
      }
    }
    print line; n++
  }
  close(path)
  if (!unset && !done) print key "=" fmt_val(val)
  return 0
}

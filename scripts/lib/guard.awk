# secure-env — análisis del hook PreToolUse (se carga junto a engine.awk con MODE=hook).
#
# Lee el payload JSON de Claude Code por stdin y escribe UNA línea:
#   ALLOW
#   DENY<TAB>mensaje para Claude
#   ASK<TAB>motivo para el usuario
#
# Modelo: fuera del wrapper run-secure se bloquea todo lo que pueda imprimir un secreto
# (leer .env, volcar el entorno, referenciar variables sensibles, trazas). Dentro del
# wrapper se permite todo, porque su salida pasa por el redactor.

BEGIN {
  if (MODE == "hook") { mode_hook(); exit 0 }
  if (MODE == "post") { mode_post(); exit 0 }
}

# ------------------------------------------------------------------ PostToolUse: red de seguridad
# Redacta el resultado de CUALQUIER herramienta (Bash, Read, Grep, WebFetch, MCP...) antes de
# que Claude lo vea. Trabaja sobre el JSON crudo de tool_response, así conserva su forma exacta
# (objeto, arreglo o string): Claude Code descarta en silencio un updatedToolOutput con otra forma.
# Imprime "NONE" si no hubo nada que redactar, o "REDACTED<TAB>claves<TAB>json-redactado".
function mode_post(   payload, raw, red, j, i, keys, seen) {
  payload = read_all()
  raw = json_raw(payload, "tool_response")
  if (raw == "") raw = json_raw(payload, "tool_output")
  if (raw == "") { print "NONE"; return }
  load_all(1); finalize()
  red = raw; keys = ""
  for (j = 1; j <= NO; j++) {
    i = OI[j]
    if (index(red, PV[i]) == 0) continue
    if (!(PK[i] in seen)) { seen[PK[i]] = 1; keys = keys (keys == "" ? "" : ", ") PK[i] }
    red = redact_one(red, PV[i], PK[i])
  }
  if (keys == "") { print "NONE"; return }
  print "REDACTED\t" keys "\t" red
}

function redact_one(s, t, k,   rep, res, pos, tl) {
  rep = "[REDACTED:" k "]"; res = ""; tl = length(t)
  while ((pos = index(s, t)) > 0) { res = res substr(s, 1, pos - 1) rep; s = substr(s, pos + tl) }
  return res s
}

# Devuelve el texto JSON crudo (sin decodificar) del valor de "key".
function json_raw(s, key,   pat, p, rest, c, i, n, depth, instr, start) {
  pat = "\"" key "\""
  while ((p = index(s, pat)) > 0) {
    rest = substr(s, p + length(pat)); s = rest
    sub(/^[ \t\r\n]*/, "", rest)
    if (substr(rest, 1, 1) != ":") continue
    rest = substr(rest, 2); sub(/^[ \t\r\n]*/, "", rest)
    c = substr(rest, 1, 1); n = length(rest)
    if (c == "\"") {
      for (i = 2; i <= n; i++) { c = substr(rest, i, 1); if (c == "\\") { i++; continue } if (c == "\"") return substr(rest, 1, i) }
      return ""
    }
    if (c == "{" || c == "[") {
      depth = 0; instr = 0
      for (i = 1; i <= n; i++) {
        c = substr(rest, i, 1)
        if (instr) { if (c == "\\") i++; else if (c == "\"") instr = 0; continue }
        if (c == "\"") instr = 1
        else if (c == "{" || c == "[") depth++
        else if (c == "}" || c == "]") { depth--; if (depth == 0) return substr(rest, 1, i) }
      }
      return ""
    }
    if (match(rest, /^[^,}\]]*/)) { rest = substr(rest, 1, RLENGTH); sub(/[ \t\r\n]+$/, "", rest); return rest }
    return ""
  }
  return ""
}

function mode_hook(   payload, tool, fp, r) {
  payload = read_all()
  tool = json_get(payload, "tool_name")
  CWD = json_get(payload, "cwd")
  if (CWD == "") CWD = ENVIRON["PWD"]
  SP = ENVIRON["SE_SCRIPTS_REL"]; if (SP == "") SP = ".claude/skills/secure-env/scripts"
  MAXB = ENVIRON["SECURE_ENV_READ_CHECK_MAX_BYTES"] + 0; if (MAXB <= 0) MAXB = 5000000
  READCHECK = (ENVIRON["SECURE_ENV_READ_CHECK"] != "0")
  SECFILERE = globs_to_re(ENVIRON["SECURE_ENV_SECRET_FILES"])
  SCRIPTRE = "(^|/)secure-env/scripts/(run-secure|list-env-keys|env-set|redact)\\.sh$"
  g_sets()
  load_all(1); finalize()

  if (tool == "Bash" || tool == "PowerShell") r = decide_cmd(json_get(payload, "command"))
  else if (tool == "Read") r = decide_read(json_get(payload, "file_path"))
  else if (tool == "Edit" || tool == "MultiEdit" || tool == "Write" || tool == "NotebookEdit") {
    fp = json_get(payload, "file_path"); if (fp == "") fp = json_get(payload, "notebook_path")
    r = decide_write(tool, fp)
  }
  else if (tool == "Grep") r = decide_grep(json_get(payload, "path"), json_get(payload, "glob"))
  else r = ""
  if (r == "") r = "ALLOW"
  print r
}

function g_sets(   i, n, a) {
  n = split("bash sh zsh dash ksh fish", a, " ");                      for (i = 1; i <= n; i++) SHELLS[a[i]] = 1
  n = split("node nodejs bun deno tsx ts-node python python3 python2 py pypy3 ruby perl php irb", a, " "); for (i = 1; i <= n; i++) INTERP[a[i]] = 1
  n = split("ls ll stat test [ [[ touch chmod chown chgrp rm unlink file wc du realpath readlink dirname basename sha256sum sha1sum sha512sum md5sum shasum md5 cksum cd pushd popd mkdir code cursor open xdg-open start explorer echo printf tee true false which whereis : test-path remove-item new-item rename-item attrib icacls exit", a, " ")
  for (i = 1; i <= n; i++) META[a[i]] = 1
  n = split("cat tac nl head tail less more most bat batcat view jq yq grep egrep fgrep rg ag ack sed awk gawk mawk nawk cut sort uniq strings xxd od hexdump column fold fmt pr iconv type get-content gc select-string sls diff cmp comm paste base64", a, " ")
  for (i = 1; i <= n; i++) READERS[a[i]] = 1
  n = split("cat tee base64 xxd od head tail rev tr sed awk cut jq less more echo printf", a, " ")
  for (i = 1; i <= n; i++) PASSTHRU[a[i]] = 1
  n = split("cp mv ln install rsync scp copy-item move-item", a, " "); for (i = 1; i <= n; i++) COPIERS[a[i]] = 1
  n = split("grep egrep fgrep rg ag ack", a, " "); for (i = 1; i <= n; i++) GREPS[a[i]] = 1
  n = split("dotenv dotenvx env-cmd dotenv-cli dotenv-flow", a, " "); for (i = 1; i <= n; i++) LOADERS[a[i]] = 1
  n = split("png jpg jpeg gif webp ico bmp tiff pdf zip gz tgz bz2 xz 7z rar jar woff woff2 ttf otf eot mp3 mp4 mov avi wav ogg webm sqlite db exe dll so dylib class pyc wasm", a, " ")
  for (i = 1; i <= n; i++) BINEXT[a[i]] = 1
}

# ------------------------------------------------------------------ mensajes

function m_wrap()   { return "`bash " SP "/run-secure.sh -- <comando>`" }
function msg_read_env(f) { return "secure-env: leer " f " directamente está bloqueado (sus valores entrarían al chat). Para ver qué variables hay: `bash " SP "/list-env-keys.sh`. Para ver el contenido con los secretos tapados: `bash " SP "/redact.sh " f "`. Para usar sus valores en un comando: " m_wrap() "." }
function msg_loader()   { return "secure-env: cargar un .env y ejecutar fuera del wrapper deja la salida sin redactar. Usa " m_wrap() " (carga .env y redacta stdout/stderr). Ej: `bash " SP "/run-secure.sh -- node app.js`." }
function msg_dump()     { return "secure-env: volcar el entorno completo está bloqueado. Para ver qué variables existen: `bash " SP "/list-env-keys.sh`. Si de verdad necesitas el entorno de un proceso, ejecútalo dentro de " m_wrap() ", que redacta los valores." }
function msg_trace()    { return "secure-env: el trazado de shell (set -x / bash -x) imprime las variables ya expandidas. Quítalo o ejecútalo dentro de " m_wrap() ", que redacta la salida." }
function msg_ref(n)     { return "secure-env: este comando usa $" n " (secreto) fuera del wrapper, así que su salida no se redacta. Ejecútalo así: `bash " SP "/run-secure.sh -- '<comando completo>'` (con comillas SIMPLES: la variable se expande adentro, con el .env cargado). Para solo verificar que existe: `bash " SP "/list-env-keys.sh`." }
function msg_outer(n)   { return "secure-env: $" n " se expandiría en tu shell, ANTES de entrar a run-secure (quedaría vacía o expuesta). Pasa el comando como un solo argumento entre comillas SIMPLES: `bash " SP "/run-secure.sh -- 'curl -sS -H \"Authorization: Bearer $" n "\" https://...'`." }
function msg_inline(n)  { return "secure-env: el código inline lee " n " del entorno y su salida no se redacta. Ejecútalo dentro de " m_wrap() "." }
function msg_verbose()  { return "secure-env: el modo verbose de curl/wget/httpie con credenciales (netrc, -K, cookies) imprime los headers de autenticación. Quita -v/--trace o ejecútalo dentro de " m_wrap() "." }
function msg_edit_env(f){ return "secure-env: editar " f " con herramientas de archivo mostraría su contenido. Usa `bash " SP "/env-set.sh [-f " f "] CLAVE VALOR` (también `--generate [bytes]` y `--unset`)." }
function msg_copy()     { return "secure-env: copiar un .env o archivo de credenciales a otra ruta lo deja legible sin protección. Si es un respaldo, usa un nombre .env.* (ej. .env.bak), que sigue protegido." }
function msg_git_add()  { return "secure-env: no se versionan archivos .env ni de credenciales. Agrégalos a .gitignore (verifica con `git check-ignore -v <archivo>`)." }
function msg_grep_rec(f) { return "secure-env: esta búsqueda recursiva también leería " f " y sus valores entrarían al chat. Exclúyelo (`grep -r --exclude='.env*' …`, en rg `-g '!.env*'`) o busca solo en las carpetas de código (ej. `grep -rn … src/`)." }
function msg_git()      { return "secure-env: ese comando git mostraría el contenido de un .env. Para saber si cambió: `git status --short <archivo>`." }
function msg_find()     { return "secure-env: find con -exec sobre archivos .env leería su contenido. Usa find solo para listar rutas, o `bash " SP "/list-env-keys.sh <archivo>`." }
function msg_secret(f)  { return "secure-env: " f " es un archivo de credenciales (llave privada, .netrc, cuenta de servicio...). No se lee ni copia desde el agente; pide al usuario lo que necesites saber." }
function msg_docker_cfg(){ return "secure-env: `docker compose config` imprime los valores interpolados del .env. Usa `--services`/`--volumes`, o ejecútalo dentro de " m_wrap() "." }
function msg_docker_insp(){ return "secure-env: `docker inspect` sin --format incluye las variables de entorno del contenedor. Pide solo los campos necesarios, ej. `--format '{{.State.Status}}'`." }
function msg_credcmd()  { return "secure-env: este comando imprime una credencial guardada (keychain, gh, gcloud, aws, 1Password, kubectl secret...). Úsala sin imprimirla, por sustitución dentro del comando que la necesita, ej. `GH_TOKEN=$(gh auth token) gh api user`, o pide al usuario lo que necesites saber." }
function msg_docker_env(){ return "secure-env: listar el entorno de un contenedor/pod imprimiría sus secretos. Consulta variables puntuales no sensibles, o pide al usuario que lo revise." }
function msg_ask(f, k)  { return "secure-env: " f " contiene el valor de " k " (de un .env o del entorno). Si apruebas, ese secreto entrará al contexto del agente. Alternativa sin exponerlo: bash " SP "/redact.sh " f }

# ------------------------------------------------------------------ utilidades

function read_all(   s, line, n) {
  s = ""; n = 0
  while ((getline line) > 0) { s = s (n++ ? "\n" : "") line }
  return s
}

function basename_of(p) { sub(/[\/\\]+$/, "", p); sub(/.*[\/\\]/, "", p); return p }

function abs_path(p) {
  if (p ~ /^\// || p ~ /^[A-Za-z]:[\\\/]/) return p
  if (p ~ /^~\//) return ENVIRON["HOME"] substr(p, 2)
  if (p == "~") return ENVIRON["HOME"]
  return CWD "/" p
}

function is_binary(p,   e) {
  e = tolower(basename_of(p))
  if (!match(e, /\.[a-z0-9]+$/)) return 0
  return (substr(e, RSTART + 1) in BINEXT)
}

function file_exists(p,   x, rc) { rc = (getline x < p); close(p); return (rc >= 0) }

# ¿El nombre de archivo (basename) es un .env con secretos? Las plantillas no cuentan.
function is_env_name(b,   lb, stem) {
  lb = tolower(b)
  if (lb == ".env" || lb == ".envrc" || lb == ".dev.vars") return 1
  if (lb ~ /^\.(env|dev\.vars)\.[a-z0-9_.-]+$/) return !is_template(substr(lb, index(lb, ".") + 1))
  if (lb ~ /^[a-z0-9_-]+\.env$/) {
    stem = substr(lb, 1, length(lb) - 4)
    if (stem ~ /^(process|meta|import|bun|deno|os|example|sample|template|default|defaults|dist|schema)$/) return 0
    return 1
  }
  return 0
}

function is_template(s) { return (s ~ /(^|\.)(example|sample|template|tpl|dist|defaults|schema)(\.|$)/) }

function is_secret_path(p,   b) {
  if (p == "") return 0
  b = basename_of(p)
  if (b ~ SECFILERE) return 1
  # globs con "/" (ej. .aws/credentials) se comparan contra el final de la ruta
  return (p ~ SECPATHRE_RE())
}

function SECPATHRE_RE(   n, a, i, out, g, r, j, c) {
  if (SECPATHRE_DONE) return SECPATHRE
  SECPATHRE_DONE = 1
  n = split(ENVIRON["SECURE_ENV_SECRET_FILES"], a, /[ \t\n,]+/); out = ""
  for (i = 1; i <= n; i++) {
    g = a[i]; if (index(g, "/") == 0) continue
    r = ""
    for (j = 1; j <= length(g); j++) {
      c = substr(g, j, 1)
      if (c == "*") r = r "[^/]*"; else if (index("\\^$.|+()[]{}?", c)) r = r "\\" c; else r = r c
    }
    out = out (out == "" ? "" : "|") r
  }
  SECPATHRE = (out == "") ? "^\001$" : "(^|/)(" out ")$"
  return SECPATHRE
}

# Busca referencias a archivos .env / de credenciales dentro de una palabra (también dentro de código).
# Deja en ES_ENV y ES_SEC la cantidad encontrada y en ES_NAME la primera.
function env_scan(w,   s, run, b) {
  ES_ENV = 0; ES_SEC = 0; ES_NAME = ""
  s = w
  while (match(s, /[A-Za-z0-9_.\/~@+-]+/)) {
    run = substr(s, RSTART, RLENGTH); s = substr(s, RSTART + RLENGTH)
    b = run; sub(/.*\//, "", b)
    if (is_env_name(b)) { ES_ENV++; if (ES_NAME == "") ES_NAME = run }
    else if (is_secret_path(run)) { ES_SEC++; if (ES_NAME == "") ES_NAME = run }
  }
  return ES_ENV + ES_SEC
}

function name_sens(n) {
  if (n in SECNAME) return 1
  return name_is_sensitive(n)
}

# Referencias de shell a variables sensibles: $X, ${X}, ${X:-y}, $env:X. Ignora ${#X} (largo).
function shell_ref(t,   s, m, name) {
  s = t
  while (match(s, /\$(\{#?)?[A-Za-z_][A-Za-z0-9_]*/)) {
    m = substr(s, RSTART, RLENGTH); s = substr(s, RSTART + RLENGTH)
    if (m ~ /^\$\{#/) continue
    name = m; sub(/^\$\{?/, "", name)
    if (name == "env" && substr(s, 1, 1) == ":") {
      if (match(s, /^:[A-Za-z_][A-Za-z0-9_]*/)) { name = substr(s, 2, RLENGTH - 1); s = substr(s, RLENGTH + 1) } else continue
    }
    if (name_sens(name)) return name
  }
  return ""
}

# Referencias en código (Node/Python/Ruby/PHP/Perl/Deno/Bun) a variables sensibles.
function code_ref(t,   s, m, name, pat) {
  pat = "(process\\.env\\.|process\\.env\\[[\"'`]|Bun\\.env\\.|import\\.meta\\.env\\.|Deno\\.env\\.get\\([\"']|os\\.environ\\[[\"']|os\\.environ\\.get\\([\"']|getenv\\([\"']|\\$_ENV\\[[\"']|\\$_SERVER\\[[\"']|ENV\\[[\"']|ENV\\.fetch\\([\"']|\\$ENV\\{|\\$env:)[A-Za-z_][A-Za-z0-9_]*"
  s = t
  while (match(s, pat)) {
    m = substr(s, RSTART, RLENGTH); s = substr(s, RSTART + RLENGTH)
    match(m, /[A-Za-z_][A-Za-z0-9_]*$/); name = substr(m, RSTART, RLENGTH)
    if (name_sens(name)) return name
  }
  return ""
}

function code_dump(t) {
  if (t ~ /process\.env([^.\[A-Za-z0-9_$]|$)/) return 1
  if (t ~ /os\.environ([^\[.A-Za-z0-9_]|$)/ || t ~ /os\.environ\.(items|copy|values)\(/) return 1
  if (t ~ /(^|[^A-Za-z0-9_$:.])ENV([^\[A-Za-z0-9_.]|$)/ || t ~ /ENV\.(to_h|to_a|to_hash|inspect|each|map|select|values)/) return 1
  if (t ~ /\$_ENV([^\[]|$)/ || t ~ /\$_SERVER([^\[]|$)/ || t ~ /getenv\([ \t]*\)/ || t ~ /phpinfo\(/) return 1
  if (t ~ /%ENV/ || t ~ /Deno\.env\.toObject\(/ || t ~ /Bun\.env([^.\[A-Za-z]|$)/) return 1
  if (tolower(t) ~ /getenvironmentvariables\(/) return 1
  return 0
}

function ps_dump(t,   l) {
  l = tolower(t)
  return (l ~ /(get-childitem|gci|dir|ls)[ \t]+env:[ \t]*($|[|;)}])/ || l ~ /getenvironmentvariables\(/)
}

# ------------------------------------------------------------------ decisiones por herramienta

function decide_read(fp,   b, key, p) {
  if (fp == "") return ""
  b = basename_of(fp)
  if (is_env_name(b)) return "DENY\t" msg_read_env(b)
  if (is_secret_path(fp)) return "DENY\t" msg_secret(b)
  if (!READCHECK || is_binary(fp)) return ""
  p = abs_path(fp)
  key = scan_file(p, MAXB)
  if (key != "") return "ASK\t" msg_ask(fp, key)
  return ""
}

function decide_write(tool, fp,   b) {
  if (fp == "") return ""
  b = basename_of(fp)
  if (is_env_name(b)) {
    if (tool == "Write" && !file_exists(abs_path(fp))) return ""
    return "DENY\t" msg_edit_env(b)
  }
  if (is_secret_path(fp)) return "DENY\t" msg_secret(b)
  return ""
}

function decide_grep(path, glob) {
  if (path != "" && (is_env_name(basename_of(path)) || is_secret_path(path))) return "DENY\t" msg_read_env(basename_of(path))
  if (glob != "") { gsub(/\*/, "", glob); if (env_scan(glob) > 0) return "DENY\t" msg_read_env(glob) }
  return ""
}

function decide_cmd(cmd,   first, r, i, key, p) {
  NS = 0; NCHK = 0
  first = tokenize(cmd, 0)
  r = analyze_range(first, NS, 0)
  if (r != "") return r
  for (i = 1; i <= NCHK; i++) {
    p = abs_path(CHK[i])
    if (is_binary(p)) continue
    key = scan_file(p, MAXB)
    if (key != "") return "ASK\t" msg_ask(CHK[i], key)
  }
  return ""
}

# ------------------------------------------------------------------ tokenizador de shell
# Produce segmentos (comandos simples) con sus palabras sin comillas.
#   SEGW[s,k] texto   SEGX[s,k] partes expandibles (fuera de comillas simples)
#   SEGR[s,k] "" | ">" (destino de escritura) | "<" (lectura) | "&" (fd) | "h" (here-string)
#   SEGEND[s] "|" si el segmento entrega su salida por pipe

function seg_new(depth) { NS++; SEGN[NS] = 0; SEGEND[NS] = ""; SEGHB[NS] = ""; SEGHBQ[NS] = 0; SEGD[NS] = depth; SEGSUB[NS] = 0; return NS }

function t_endword() {
  if (T_have) {
    if (T_pend == "H") { T_hd = T_cur; T_hdq = T_curq; T_hds = T_s }
    else { SEGN[T_s]++; SEGW[T_s, SEGN[T_s]] = T_cur; SEGX[T_s, SEGN[T_s]] = T_x; SEGR[T_s, SEGN[T_s]] = T_pend }
    T_pend = ""
  }
  T_cur = ""; T_x = ""; T_have = 0; T_curq = 0
}

function t_sep(kind,   sub0) { t_endword(); SEGEND[T_s] = kind; sub0 = SEGSUB[T_s]; T_s = seg_new(T_depth); SEGSUB[T_s] = sub0 }

function t_push(kind) {
  T_sp++; T_stk_s[T_sp] = T_s; T_stk_cur[T_sp] = T_cur; T_stk_x[T_sp] = T_x; T_stk_have[T_sp] = T_have
  T_stk_q[T_sp] = T_q; T_stk_k[T_sp] = kind; T_stk_pend[T_sp] = T_pend
  T_cur = ""; T_x = ""; T_have = 0; T_q = ""; T_pend = ""
  T_s = seg_new(T_depth)
  SEGSUB[T_s] = (kind == "$" || kind == "`")   # su salida se captura, no se imprime
}

function t_pop() {
  t_endword()
  T_s = T_stk_s[T_sp]; T_cur = T_stk_cur[T_sp] "$(...)"; T_x = T_stk_x[T_sp]; T_have = 1
  T_q = T_stk_q[T_sp]; T_pend = T_stk_pend[T_sp]; T_sp--
}

function t_heredoc_body(str, i, n,   rest, line, body, nl, delim, cmp) {
  body = ""
  while (i < n) {
    rest = substr(str, i + 1)
    nl = index(rest, "\n")
    line = (nl ? substr(rest, 1, nl - 1) : rest)
    i += (nl ? nl : length(rest))
    cmp = line; if (T_hddash) sub(/^\t+/, "", cmp)
    if (cmp == T_hd) break
    body = body line "\n"
  }
  SEGHB[T_hds] = SEGHB[T_hds] body; SEGHBQ[T_hds] = T_hdq
  T_hd = ""
  return i
}

function tokenize(str, depth,   n, i, c, c2, c3, j, start) {
  n = length(str)
  T_depth = depth; T_s = seg_new(depth); start = T_s
  T_q = ""; T_cur = ""; T_x = ""; T_have = 0; T_curq = 0; T_pend = ""; T_sp = 0; T_hd = ""; T_hddash = 0
  for (i = 1; i <= n; i++) {
    c = substr(str, i, 1); c2 = substr(str, i, 2)
    if (T_q == "'") { if (c == "'") T_q = ""; else T_cur = T_cur c; continue }
    if (c == "\\") {
      if (i == n) { T_cur = T_cur c; T_x = T_x c; T_have = 1; continue }
      j = substr(str, i + 1, 1)
      if (T_q == "\"" && j !~ /[$`"\\\n]/) { T_cur = T_cur c; T_x = T_x c }
      if (j != "\n") { T_cur = T_cur j; T_x = T_x j }
      T_have = 1; i++; continue
    }
    if (c2 == "$(" ) {
      if (substr(str, i + 2, 1) == "(") {  # $(( aritmética )): se copia tal cual
        j = index(substr(str, i), "))"); if (j == 0) j = n - i
        T_cur = T_cur substr(str, i, j + 1); T_x = T_x substr(str, i, j + 1); T_have = 1; i += j; continue
      }
      t_push("$"); i++; continue
    }
    if (c == "`") {
      if (T_sp > 0 && T_stk_k[T_sp] == "`") t_pop(); else t_push("`")
      continue
    }
    if (T_q == "\"") {
      if (c == "\"") { T_q = ""; continue }
      T_cur = T_cur c; T_x = T_x c; continue
    }
    # --- fuera de comillas
    if (c == "'" || c == "\"") { T_q = c; T_have = 1; T_curq = 1; continue }
    if (c == " " || c == "\t") { t_endword(); continue }
    if (c == "\n") {
      t_sep(";")
      if (T_hd != "") i = t_heredoc_body(str, i, n)
      continue
    }
    if (c == "#" && !T_have) { j = index(substr(str, i), "\n"); if (j == 0) break; i += j - 2; continue }
    if (c == ";") { t_sep(";"); continue }
    if (c == "&") {
      if (c2 == "&&") { i++; t_sep(";"); continue }
      if (c2 == "&>") { t_endword(); i++; if (substr(str, i + 1, 1) == ">") i++; T_pend = ">"; continue }
      t_sep(";"); continue
    }
    if (c == "|") {
      if (c2 == "||") { i++; t_sep(";"); continue }
      if (c2 == "|&") i++
      t_sep("|"); continue
    }
    if (c == "(") { t_endword(); t_push("("); continue }
    if (c == ")") { if (T_sp > 0) t_pop(); else t_sep(";"); continue }
    if (c == ">" || c == "<") {
      if (substr(str, i + 1, 1) == "(") { t_endword(); t_push("("); i++; continue }  # <( ) / >( )
      if (T_have && !T_curq && T_cur ~ /^[0-9]+$/) { T_cur = ""; T_x = ""; T_have = 0 } else t_endword()
      c3 = substr(str, i, 3)
      if (c3 == "<<<") { T_pend = "h"; i += 2; continue }
      if (c2 == "<<") { i++; if (substr(str, i + 1, 1) == "-") { T_hddash = 1; i++ } else T_hddash = 0; T_pend = "H"; continue }
      if (c2 == ">>") { T_pend = ">"; i++; continue }
      if (c2 == ">&" || c2 == "<&") { T_pend = "&"; i++; continue }
      if (c2 == ">|" || c2 == "<>") { T_pend = ">"; i++; continue }
      T_pend = (c == ">") ? ">" : "<"; continue
    }
    T_cur = T_cur c; T_x = T_x c; T_have = 1
  }
  t_endword()
  while (T_sp > 0) t_pop()
  t_endword()
  return start
}

# ------------------------------------------------------------------ análisis de segmentos

function analyze_range(a, b, depth,   s, r) {
  for (s = a; s <= b; s++) { r = analyze_seg(s, depth); if (r != "") return r }
  return ""
}

function cmdbase(w) { sub(/.*[\/\\]/, "", w); w = tolower(w); sub(/\.(exe|cmd|bat)$/, "", w); return w }

function is_assign(w) { return (w ~ /^[A-Za-z_][A-Za-z0-9_]*\+?=/) }

# Calcula P[] (palabras posicionales), CI (índice del comando) y CMD para el segmento s.
function seg_words(s,   k, np, i, c, w) {
  np = 0; OUTRED = 0; HSTR = ""; HSTRX = ""; INSRC_ENV = ""; ENVDUMP = 0
  for (k = 1; k <= SEGN[s]; k++) {
    w = SEGW[s, k]
    if (SEGR[s, k] == "") { np++; P[np] = w; PX[np] = SEGX[s, k] }
    else if (SEGR[s, k] == ">") { OUTRED = 1 }
    else if (SEGR[s, k] == "<") { if (env_scan(w) > 0) INSRC_ENV = w; else CHK[++NCHK] = w }
    else if (SEGR[s, k] == "h") { HSTR = HSTR " " w; HSTRX = HSTRX " " SEGX[s, k] }
  }
  NP_ = np
  i = 1
  while (i <= np && is_assign(P[i])) i++
  # envoltorios que no son el comando real
  while (i <= np) {
    c = cmdbase(P[i])
    if (c == "sudo" || c == "doas") { i++; while (i <= np && P[i] ~ /^-/) { if (P[i] ~ /^-[ugCDhpRrtU]$/) i++; i++ } continue }
    if (c == "command" || c == "builtin" || c == "exec" || c == "nohup" || c == "time" || c == "stdbuf" || c == "unbuffer" || c == "winpty" || c == "caffeinate") { i++; while (i <= np && P[i] ~ /^-/) i++; continue }
    if (c == "nice") { i++; if (P[i] == "-n") i += 2; else if (P[i] ~ /^-/) i++; continue }
    if (c == "timeout") { i++; while (i <= np && P[i] ~ /^-/) { if (P[i] ~ /^-(s|k)$/) i++; i++ } i++; continue }
    if (c == "env") {
      i++
      while (i <= np && (P[i] ~ /^-/ || is_assign(P[i]))) { if (P[i] ~ /^-(u|C|S)$/) i++; i++ }
      if (i > np) { ENVDUMP = 1; i = np + 1 }
      continue
    }
    if (c == "npx" || c == "bunx" || c == "pnpx") { i++; while (i <= np && P[i] ~ /^-/) { if (P[i] ~ /^-(p|-package)$/) i++; i++ } continue }
    if ((c == "pnpm" || c == "yarn") && (P[i + 1] == "exec" || P[i + 1] == "dlx")) { i += 2; continue }
    if (c == "xargs") { i++; while (i <= np && P[i] ~ /^-/) { if (P[i] ~ /^-[IdnLPsEa]$/) i++; i++ } continue }
    break
  }
  CI = i
  CMD = (ENVDUMP ? "env" : (i <= np ? cmdbase(P[i]) : ""))
  return np
}

function seg_peek_cmd(s,   k, w) {
  if (s > NS) return ""
  for (k = 1; k <= SEGN[s]; k++) {
    if (SEGR[s, k] != "") continue
    w = SEGW[s, k]
    if (is_assign(w)) continue
    if (cmdbase(w) ~ /^(sudo|command|exec|nohup|time|xargs|env)$/) continue
    return cmdbase(w)
  }
  return ""
}

function analyze_seg(s, depth,   np, k, w, a, j, sub1, last, n, code, rf, envAny, nonLastEnv, lastEnv, envw, secAny, joined, re, nre, ALW, txt, nxt) {
  if (SEGN[s] == 0) return ""
  np = seg_words(s)
  if (INSRC_ENV != "" && !(CI <= np && P[CI] ~ SCRIPTRE)) return "DENY\t" msg_read_env(INSRC_ENV)
  if (CI > np && !ENVDUMP) {
    # solo asignaciones: X=$(...) se analiza en su propio segmento; aquí nada que imprimir
    return ""
  }

  # 1) Nuestros scripts: run-secure permite todo lo que va dentro (su salida se redacta),
  #    salvo que una variable secreta se expanda AFUERA (quedaría vacía o en la línea de comando).
  a = 0
  if (P[CI] ~ SCRIPTRE) a = CI
  else if (CMD in SHELLS) { for (k = CI + 1; k <= np; k++) { if (P[k] ~ /^-/) continue; if (P[k] ~ SCRIPTRE) a = k; break } }
  if (a) {
    if (P[a] ~ /run-secure\.sh$/) {
      txt = ""; for (k = a + 1; k <= np; k++) txt = txt " " PX[k]
      rf = shell_ref(txt); if (rf != "") return "DENY\t" msg_outer(rf)
    }
    return ""
  }

  # 2) Lista blanca configurable
  joined = ""
  for (k = CI; k <= np; k++) joined = joined (joined == "" ? "" : " ") P[k]
  nre = split(ENVIRON["SECURE_ENV_ALLOW_COMMANDS"], ALW, "\n")
  for (j = 1; j <= nre; j++) { re = ALW[j]; if (re != "" && joined ~ re) return "" }

  # 3) Trazas de shell
  if (CMD == "set") {
    for (k = CI + 1; k <= np; k++) { if (P[k] ~ /^-[A-Za-z]*x/) return "DENY\t" msg_trace(); if (P[k] == "-o" && P[k + 1] == "xtrace") return "DENY\t" msg_trace() }
    if (CI == np) return "DENY\t" msg_dump()
  }
  if (CMD in SHELLS) {
    for (k = CI + 1; k <= np; k++) {
      if (P[k] !~ /^-/) break
      if (P[k] ~ /^-[A-Za-z]*x[A-Za-z]*$/) return "DENY\t" msg_trace()
      if (P[k] == "-o" && P[k + 1] == "xtrace") return "DENY\t" msg_trace()
    }
  }

  # 4) Volcados del entorno
  if (CMD == "env" && ENVDUMP) return "DENY\t" msg_dump()
  if (CMD == "printenv") {
    a = 0
    for (k = CI + 1; k <= np; k++) { if (P[k] ~ /^-/) continue; a++; if (name_sens(P[k])) return "DENY\t" msg_ref(P[k]) }
    if (a == 0) return "DENY\t" msg_dump()
  }
  if (CMD == "export" || CMD == "declare" || CMD == "typeset") {
    a = 0
    for (k = CI + 1; k <= np; k++) {
      if (P[k] ~ /^-/) continue
      a++
      if (CMD != "export" && P[k] !~ /=/ && name_sens(P[k])) return "DENY\t" msg_ref(P[k])
    }
    if (a == 0) return "DENY\t" msg_dump()
  }
  for (k = CI; k <= np; k++) if (ps_dump(P[k])) return "DENY\t" msg_dump()

  # 5) Shells e intérpretes: analizar el código que reciben
  if (depth < 4 && (CMD in SHELLS)) {
    for (k = CI + 1; k <= np; k++) {
      if (P[k] ~ /^-[A-Za-z]*c[A-Za-z]*$/ && k < np) { rf = analyze_code(P[k + 1], depth); if (rf != "") return rf; break }
      if (P[k] !~ /^-/) break
    }
  }
  if (depth < 4 && (CMD == "pwsh" || CMD == "powershell")) {
    for (k = CI + 1; k <= np; k++) {
      if (tolower(P[k]) ~ /^-(c|command)$/) {
        code = ""; for (j = k + 1; j <= np; j++) code = code " " P[j]
        if (code_dump(code) || ps_dump(code)) return "DENY\t" msg_dump()
        rf = analyze_code(code, depth); if (rf != "") return rf
        break
      }
    }
  }
  if (depth < 4 && CMD == "eval") {
    code = ""; for (j = CI + 1; j <= np; j++) code = code " " P[j]
    rf = analyze_code(code, depth); if (rf != "") return rf
  }
  if (CMD in INTERP) {
    for (k = CI + 1; k <= np; k++) {
      if (code_dump(P[k])) return "DENY\t" msg_dump()
      rf = code_ref(P[k]); if (rf != "") return "DENY\t" msg_inline(rf)
    }
    if (SEGHB[s] != "") {
      if (code_dump(SEGHB[s])) return "DENY\t" msg_dump()
      rf = code_ref(SEGHB[s]); if (rf != "") return "DENY\t" msg_inline(rf)
    }
    for (k = CI + 1; k < np; k++) if (P[k] == "-m" && P[k + 1] ~ /^dotenv/) return "DENY\t" msg_loader()
  }

  # 6) Loaders de .env
  if (CMD in LOADERS) return "DENY\t" msg_loader()
  for (k = CI; k <= np; k++) if (P[k] ~ /^--env-file(=|$)/) return "DENY\t" msg_loader()

  # 7) HTTP verbose con credenciales implícitas
  if (CMD == "curl" || CMD == "wget" || CMD == "http" || CMD == "https" || CMD == "xh") {
    a = 0; rf = 0
    for (k = CI + 1; k <= np; k++) {
      w = P[k]
      if (w == "--verbose" || w ~ /^--trace/ || w == "--debug" || w == "--offline" || w ~ /^--print=.*H/) a = 1
      else if (w ~ /^-[A-Za-z0-9#]*v[A-Za-z0-9#]*$/ && CMD != "wget") a = 1
      else if (w == "-d" && CMD == "wget") a = 1
      if (w ~ /^(-n|--netrc|--netrc-file|--netrc-optional|-K|--config|-b|--cookie|-E|--cert|--key|--oauth2-bearer)(=|$)/) rf = 1
    }
    if (a && rf) return "DENY\t" msg_verbose()
  }

  # 8) Docker / kubectl
  if (CMD == "docker" || CMD == "podman" || CMD == "docker-compose" || CMD == "kubectl") {
    n = 0
    for (k = CI + 1; k <= np; k++) if (P[k] !~ /^-/) { n++; A1[n] = P[k] }
    if (CMD == "docker-compose" || A1[1] == "compose") {
      a = 0; for (k = CI + 1; k <= np; k++) if (P[k] == "config") a = 1
      if (a) {
        for (k = CI + 1; k <= np; k++) if (P[k] ~ /^(--services|--volumes|--images|--profiles|--networks|--hash|-q|--quiet|--variables)$/) a = 0
        if (a) return "DENY\t" msg_docker_cfg()
      }
    }
    if (CMD != "kubectl" && (A1[1] == "inspect" || ((A1[1] == "container" || A1[1] == "image") && A1[2] == "inspect"))) {
      a = 1; for (k = CI + 1; k <= np; k++) if (P[k] ~ /^(-f|--format)(=|$)/) a = 0
      if (a) return "DENY\t" msg_docker_insp()
    }
    for (k = CI + 1; k <= np; k++) if (P[k] == "exec" || P[k] == "run") {
      if (P[np] == "env" || P[np] == "printenv" || P[np] ~ /^(env|printenv)$/) return "DENY\t" msg_docker_env()
    }
    for (k = 1; k <= n; k++) delete A1[k]
  }

  # 8b) Comandos que imprimen credenciales de un gestor (no están en .env, así que no se pueden redactar).
  #     Dentro de $(...) su salida se captura, no se imprime: se permite.
  if (!SEGSUB[s] && is_cred_printer(np)) return "DENY\t" msg_credcmd()

  # 9) Variables sensibles usadas fuera del wrapper
  if (!(CMD == "unset" || CMD == "test" || CMD == "[" || CMD == "[[" || CMD == "readonly" || CMD == "local" || CMD == "export")) {
    txt = ""
    for (k = CI; k <= np; k++) txt = txt " " PX[k]
    txt = txt " " HSTRX
    if (SEGHB[s] != "" && !SEGHBQ[s]) txt = txt " " SEGHB[s]
    rf = shell_ref(txt)
    if (rf != "") {
      # escribir a un archivo con echo/printf/cat es aceptable (no llega al chat)
      if (!(OUTRED && (CMD == "echo" || CMD == "printf" || CMD == "cat" || CMD == "tee"))) {
        if (SEGEND[s] == "|" && (CMD == "echo" || CMD == "printf")) {
          nxt = seg_peek_cmd(s + 1)
          if (nxt != "" && !(nxt in PASSTHRU)) rf = ""
        }
        if (rf != "") return "DENY\t" msg_ref(rf)
      }
    }
  }

  # 10) Referencias a archivos .env o de credenciales
  envAny = 0; secAny = 0; envw = ""
  text_args(np)
  for (k = 1; k <= np; k++) {
    ENVPOS[k] = 0
    if (k in TXT) continue
    if (env_scan(P[k]) > 0) { ENVPOS[k] = 1; envAny += ES_ENV; secAny += ES_SEC; if (envw == "") envw = ES_NAME }
  }
  if (envAny || secAny) {
    if (CMD in META) return ""
    if (CMD in COPIERS) {
      last = 0; for (k = CI + 1; k <= np; k++) if (P[k] !~ /^-/) last = k
      nonLastEnv = 0; for (k = CI + 1; k < last; k++) if (ENVPOS[k] && P[k] !~ /^-/) nonLastEnv = 1
      lastEnv = (last > 0 && env_scan(P[last]) > 0 && ES_ENV > 0)
      if (nonLastEnv && !lastEnv) return "DENY\t" (secAny ? msg_secret(envw) : msg_copy())
      return ""
    }
    if (CMD == "git") {
      sub1 = ""; for (k = CI + 1; k <= np; k++) if (P[k] !~ /^-/) { sub1 = P[k]; break }
      if (sub1 ~ /^(check-ignore|rm|ls-files|status|mv|check-attr)$/) return ""
      if (sub1 == "add" || sub1 == "stage") return "DENY\t" msg_git_add()
      return "DENY\t" msg_git()
    }
    if (CMD == "find") {
      for (k = CI + 1; k <= np; k++) if (P[k] ~ /^-(exec|execdir|ok|okdir|fprint|fprintf|fls)$/) return "DENY\t" msg_find()
      return ""
    }
    if (secAny && !envAny) return "DENY\t" msg_secret(envw)
    if (CMD == "source" || CMD == "." || CMD == "docker" || CMD == "docker-compose") return "DENY\t" msg_loader()
    return "DENY\t" msg_read_env(envw)
  }

  # 10b) Búsqueda recursiva sobre una carpeta que contiene un .env: lo lee aunque no se nombre.
  if (CMD in GREPS) { rf = grep_rec_env(np); if (rf != "") return "DENY\t" msg_grep_rec(rf) }

  # 11) Lectores de archivos comunes: revisar si el archivo contiene un secreto
  if (CMD in READERS) for (k = CI + 1; k <= np; k++) if (P[k] !~ /^-/ && !(k in TXT)) CHK[++NCHK] = P[k]
  return ""
}

# Marca en TXT las palabras que son texto y no rutas: el mensaje de `git commit -m`, y en grep/rg/ag/ack
# el patrón, los valores de opciones y las exclusiones. En GREXCL queda si alguna exclusión cubre los .env.
# En grep, GREPPATHS/NGP quedan con las rutas a buscar.
function text_args(np,   k, w, pat, explicit, takes) {
  split("", TXT); GREXCL = 0; NGP = 0
  if (CMD == "git") {
    for (k = CI + 1; k <= np; k++) {
      w = P[k]
      if ((w ~ /^-[A-Za-z]*m$/ || w == "--message") && k < np) TXT[k + 1] = 1   # -m, -am
      else if (w ~ /^--message=/ || w ~ /^-m./) TXT[k] = 1
    }
    return
  }
  if (!(CMD in GREPS)) return
  # opciones que llevan su valor en la palabra siguiente
  takes = (CMD == "rg") ? "^(-e|-f|-g|-t|-T|-m|-A|-B|-C|-M|-j|-r|-E|--regexp|--file|--glob|--iglob|--type|--type-not|--max-count|--context|--before-context|--after-context|--replace|--encoding|--max-filesize|--ignore-file)$" \
                        : "^(-e|-f|-m|-A|-B|-C|-d|-D|--regexp|--file|--max-count|--context|--before-context|--after-context|--include|--exclude|--exclude-dir|--exclude-from|--label|--ignore-dir|--ignore-file)$"
  explicit = 0
  for (k = CI + 1; k <= np; k++) if (P[k] ~ /^(-e|--regexp)(=|$)/ || P[k] ~ /^-[A-Za-z]*e$/) explicit = 1
  pat = explicit
  for (k = CI + 1; k <= np; k++) {
    w = P[k]
    if (w ~ /^--(exclude|exclude-dir|ignore-dir|ignore-file|glob|iglob)=/ ) { TXT[k] = 1; if (w ~ /=!?[^=]*env/ && w !~ /^--glob=[^!]/ && w !~ /^--iglob=[^!]/) GREXCL = 1; continue }
    if (w ~ /^--(regexp|include)=/) { TXT[k] = 1; continue }
    if (w ~ takes && k < np) {
      k++
      if (w ~ /^(-f|--file)$/) continue                       # -f lee patrones de un archivo: es una ruta
      TXT[k] = 1
      if (w ~ /^(--exclude|--exclude-dir|--ignore-dir|--ignore-file)$/ && P[k] ~ /env/) GREXCL = 1
      if (w ~ /^(-g|--glob|--iglob)$/ && P[k] ~ /^!.*env/) GREXCL = 1
      continue
    }
    if (w ~ /^-/) continue
    if (!pat) { TXT[k] = 1; pat = 1; continue }               # primer argumento suelto = patrón
    GREPPATHS[++NGP] = w
  }
}

# ¿Esta búsqueda recorre una carpeta del proyecto que contiene un .env? Devuelve su nombre o "".
# grep/ack entran a archivos ocultos; rg y ag solo con --hidden/-u (por defecto saltan ocultos e ignorados).
function grep_rec_env(np,   k, w, rec, n, F, i, j, t, f) {
  if (GREXCL) return ""
  rec = 0
  for (k = CI + 1; k <= np; k++) {
    w = P[k]; if (k in TXT) continue
    if (CMD == "rg" || CMD == "ag") { if (w ~ /^(--hidden|--unrestricted|-[A-Za-z]*u[A-Za-z]*|-\.)$/) rec = 1 }
    else if (CMD == "ack") rec = 1
    else if (w ~ /^(--recursive|--dereference-recursive)$/ || w ~ /^-[A-Za-z]*[rR][A-Za-z]*$/) rec = 1
  }
  if (CMD == "ack") rec = 1
  if (!rec) return ""
  if (NGP == 0) GREPPATHS[++NGP] = "."
  n = split(ENVIRON["SE_ENVFILES"], F, SEP)
  for (j = 1; j <= NGP; j++) {
    t = abs_path(GREPPATHS[j]); gsub(/\/\.\//, "/", t); sub(/\/\.?$/, "", t); sub(/\/+$/, "", t)
    for (i = 1; i <= n; i++) {
      f = F[i]; if (f == "" || !is_env_name(basename_of(f))) continue
      if (f == t || index(f, t "/") == 1) return basename_of(f)
    }
  }
  return ""
}

function has_word(np, re,   k) { for (k = CI + 1; k <= np; k++) if (P[k] ~ re) return 1; return 0 }
function sub_n(np, n,   k, c) { c = 0; for (k = CI + 1; k <= np; k++) if (P[k] !~ /^-/) { c++; if (c == n) return P[k] } return "" }

function is_cred_printer(np,   s1, s2, s3) {
  s1 = sub_n(np, 1); s2 = sub_n(np, 2); s3 = sub_n(np, 3)
  if (CMD == "gh" && s1 == "auth" && (s2 == "token" || (s2 == "status" && has_word(np, "^(-t|--show-token)$")))) return 1
  if (CMD == "aws" && s1 == "configure" && (s2 == "export-credentials" || (s2 == "get" && tolower(s3) ~ /(secret|token|key)/))) return 1
  if (CMD == "aws" && s1 == "ecr" && s2 ~ /^get-login-password$/) return 1
  if (CMD == "gcloud" && s1 == "auth" && s2 ~ /^print-(access|identity)-token$/) return 1
  if (CMD == "az" && s1 == "account" && s2 == "get-access-token") return 1
  if (CMD == "security" && s1 ~ /^find-(generic|internet)-password$/ && has_word(np, "^-[a-zA-Z]*[wg]$")) return 1
  if (CMD == "op" && (s1 == "read" || (s1 == "item" && s2 == "get" && has_word(np, "^(--reveal|--fields.*)$")) || s1 == "inject")) return 1
  if (CMD == "kubectl" && s1 == "get" && s2 ~ /^secrets?$/ && has_word(np, "^(-o|--output)(=?(yaml|json|jsonpath.*|go-template.*))?$")) return 1
  if (CMD == "kubectl" && s1 == "get" && s2 ~ /^secrets?\// && has_word(np, "^(-o|--output)")) return 1
  if (CMD == "heroku" && s1 ~ /^config(:get)?$/) return 1
  if ((CMD == "doppler" || CMD == "infisical") && s1 == "secrets" && (s2 == "" || s2 ~ /^(get|download|export)$/)) return 1
  if (CMD == "vault" && (s1 == "read" || (s1 == "kv" && s2 == "get"))) return 1
  if (CMD == "git" && s1 == "credential" && s2 == "fill") return 1
  if (CMD == "npm" && s1 == "token" && s2 == "create") return 1
  return 0
}

function analyze_code(code, depth,   a, b) {
  a = NS + 1
  tokenize(code, depth + 1)
  b = NS
  return analyze_range(a, b, depth + 1)
}

# ------------------------------------------------------------------ JSON mínimo (sin dependencias)

function json_get(s, key,   pat, p, rest, i, n, c, out, h) {
  pat = "\"" key "\""
  while ((p = index(s, pat)) > 0) {
    rest = substr(s, p + length(pat))
    s = rest
    sub(/^[ \t\r\n]*/, "", rest)
    if (substr(rest, 1, 1) != ":") continue
    rest = substr(rest, 2); sub(/^[ \t\r\n]*/, "", rest)
    if (substr(rest, 1, 1) != "\"") return ""
    out = ""; n = length(rest)
    for (i = 2; i <= n; i++) {
      c = substr(rest, i, 1)
      if (c == "\"") return out
      if (c == "\\") {
        i++; c = substr(rest, i, 1)
        if (c == "n") out = out "\n"
        else if (c == "t") out = out "\t"
        else if (c == "r") out = out "\r"
        else if (c == "b") out = out "\b"
        else if (c == "f") out = out "\f"
        else if (c == "u") { h = substr(rest, i + 1, 4); out = out utf8(hexval(h)); i += 4 }
        else out = out c
        continue
      }
      out = out c
    }
    return out
  }
  return ""
}

function hexval(h,   i, v, c) {
  v = 0
  for (i = 1; i <= length(h); i++) { c = index("0123456789abcdef", tolower(substr(h, i, 1))) - 1; if (c < 0) return 63; v = v * 16 + c }
  return v
}

function utf8(cp) {
  if (cp < 128) return sprintf("%c", cp)
  if (cp < 2048) return sprintf("%c%c", 192 + int(cp / 64), 128 + cp % 64)
  return sprintf("%c%c%c", 224 + int(cp / 4096), 128 + int(cp / 64) % 64, 128 + cp % 64)
}

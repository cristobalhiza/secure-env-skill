# secure-env — configuración del equipo (versionada).
# Ajustes personales: crea config.local.sh al lado (no lo versiones); se carga después de este.
# Todas las variables se pueden sobreescribir también desde el entorno.

# Variables que nunca se tratan como secretas (globs separados por espacio).
# Las *_PUBLIC_* / VITE_* / REACT_APP_* terminan en el bundle del navegador: ya son públicas.
: "${SECURE_ENV_PUBLIC_VARS:=PORT HOST HOSTNAME NODE_ENV APP_ENV ENV ENVIRONMENT TZ LANG LOG_LEVEL DEBUG CI NEXT_PUBLIC_* VITE_* PUBLIC_* EXPO_PUBLIC_* REACT_APP_* NUXT_PUBLIC_*}"

# Variables que SIEMPRE son secretas aunque su nombre o valor parezcan inocentes (globs).
# Ej: "HUBSPOT_PORTAL_ID CLIENT_*_ID"
: "${SECURE_ENV_SECRET_VARS:=}"

# 1 = todo valor de .env que no sea público se redacta (sin heurística por nombre/forma).
# 0 = los nombres neutros (DB_HOST, AWS_REGION, API_BASE_URL) solo se redactan si el valor
#     parece un secreto (token largo, URL con credenciales o con un token en la ruta).
: "${SECURE_ENV_STRICT:=0}"

# Largo mínimo de un valor para considerarlo secreto (evita redactar "1", "dev", etc.).
: "${SECURE_ENV_MIN_LEN:=6}"

# 1 = también redactar valores puramente numéricos con nombre neutro (IDs de cuenta, etc.).
: "${SECURE_ENV_REDACT_NUMERIC:=0}"

# Profundidad de búsqueda de archivos .env dentro del proyecto.
: "${SECURE_ENV_SCAN_DEPTH:=4}"

# Archivos .env adicionales fuera del proyecto (rutas separadas por espacio). Ej: ~/.secrets/clientes.env
: "${SECURE_ENV_EXTRA_FILES:=}"

# Archivos de credenciales que el agente no lee ni copia (globs; con "/" se comparan contra el final de la ruta).
: "${SECURE_ENV_SECRET_FILES:=id_rsa id_dsa id_ecdsa id_ed25519 .netrc _netrc .pgpass .git-credentials *.p12 *.pfx *.keystore *.jks service-account*.json *-service-account.json .aws/credentials .docker/config.json .config/gh/hosts.yml}"

# Al leer cualquier archivo (Read, cat, tail...), preguntar si contiene el valor de un secreto.
: "${SECURE_ENV_READ_CHECK:=1}"
: "${SECURE_ENV_READ_CHECK_MAX_BYTES:=5000000}"

# Comandos que pueden mencionar archivos .env sin pasar por run-secure.
# Una regex ERE por línea, contra el comando sin comillas (desde el nombre del comando).
: "${SECURE_ENV_ALLOW_COMMANDS:=^vercel env pull( |$)
^netlify env:import( |$)
^dotenvx (encrypt|keypair|set)( |$)}"

export SECURE_ENV_PUBLIC_VARS SECURE_ENV_SECRET_VARS SECURE_ENV_STRICT SECURE_ENV_MIN_LEN \
  SECURE_ENV_REDACT_NUMERIC SECURE_ENV_SCAN_DEPTH SECURE_ENV_EXTRA_FILES SECURE_ENV_SECRET_FILES \
  SECURE_ENV_READ_CHECK SECURE_ENV_READ_CHECK_MAX_BYTES SECURE_ENV_ALLOW_COMMANDS

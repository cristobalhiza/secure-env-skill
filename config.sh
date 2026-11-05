# secure-env — team configuration (committed).
# Personal settings: create config.local.sh next to it (don't commit it); it's loaded after this one.
# Every variable can also be overridden from the environment.

# Variables that are never treated as secrets (space-separated globs).
# *_PUBLIC_* / VITE_* / REACT_APP_* end up in the browser bundle: they are already public.
: "${SECURE_ENV_PUBLIC_VARS:=PORT HOST HOSTNAME NODE_ENV APP_ENV ENV ENVIRONMENT TZ LANG LOG_LEVEL DEBUG CI NEXT_PUBLIC_* VITE_* PUBLIC_* EXPO_PUBLIC_* REACT_APP_* NUXT_PUBLIC_*}"

# Variables that are ALWAYS secret even if their name or value look harmless (globs).
# E.g.: "HUBSPOT_PORTAL_ID CLIENT_*_ID"
: "${SECURE_ENV_SECRET_VARS:=}"

# 1 = every non-public .env value is redacted (no name/shape heuristics).
# 0 = neutral names (DB_HOST, AWS_REGION, API_BASE_URL) are only redacted if the value
#     looks like a secret (long token, URL with credentials or with a token in the path).
: "${SECURE_ENV_STRICT:=0}"

# Minimum length for a value to be considered secret (avoids redacting "1", "dev", etc.).
: "${SECURE_ENV_MIN_LEN:=6}"

# 1 = also redact purely numeric values with neutral names (account IDs, etc.).
: "${SECURE_ENV_REDACT_NUMERIC:=0}"

# Search depth for .env files inside the project.
: "${SECURE_ENV_SCAN_DEPTH:=4}"

# Extra .env files outside the project (space-separated paths). E.g.: ~/.secrets/clients.env
: "${SECURE_ENV_EXTRA_FILES:=}"

# Credential files the agent never reads or copies (globs; with "/" they're matched against the end of the path).
: "${SECURE_ENV_SECRET_FILES:=id_rsa id_dsa id_ecdsa id_ed25519 .netrc _netrc .pgpass .git-credentials *.p12 *.pfx *.keystore *.jks service-account*.json *-service-account.json .aws/credentials .docker/config.json .config/gh/hosts.yml}"

# When reading any file (Read, cat, tail...), ask if it contains a secret value.
: "${SECURE_ENV_READ_CHECK:=1}"
: "${SECURE_ENV_READ_CHECK_MAX_BYTES:=5000000}"

# Commands allowed to mention .env files without going through run-secure.
# One ERE regex per line, matched against the unquoted command (from the command name).
: "${SECURE_ENV_ALLOW_COMMANDS:=^vercel env pull( |$)
^netlify env:import( |$)
^dotenvx (encrypt|keypair|set)( |$)}"

export SECURE_ENV_PUBLIC_VARS SECURE_ENV_SECRET_VARS SECURE_ENV_STRICT SECURE_ENV_MIN_LEN \
  SECURE_ENV_REDACT_NUMERIC SECURE_ENV_SCAN_DEPTH SECURE_ENV_EXTRA_FILES SECURE_ENV_SECRET_FILES \
  SECURE_ENV_READ_CHECK SECURE_ENV_READ_CHECK_MAX_BYTES SECURE_ENV_ALLOW_COMMANDS

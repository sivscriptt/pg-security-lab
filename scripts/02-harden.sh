#!/usr/bin/env bash
# Fix everything the checklist found. Order matters: SCRAM first so every password set
# after it is hashed with SCRAM, and pg_hba.conf last so nothing locks us out halfway.
source "$(dirname "$0")/lib.sh"
need_up
[ -f "$PGPASSFILE" ] && die "already hardened (run 01-init.sh to start over)"
umask 077
mkdir -p "$TLS" "$LAB_DIR/keys"

log "SCRAM for new passwords"
q -d postgres -c "alter system set password_encryption = 'scram-sha-256'" -c "select pg_reload_conf()" >/dev/null

log "keys for pgcrypto (kept outside the database, mode 600)"
openssl rand -hex 32 > "$LAB_DIR/keys/pii.key"
openssl rand -hex 32 > "$LAB_DIR/keys/hash.key"

log "roles, row level security, encryption, audit trail"
q -v pii_key="$(cat "$LAB_DIR/keys/pii.key")" -v hash_key="$(cat "$LAB_DIR/keys/hash.key")" -f "$LAB_ROOT/sql/harden.sql" >/dev/null
ok "national IDs encrypted: $(q -c "select count(*) from core.customers where national_id_enc is not null")"

log "new random passwords for every login, hashed with SCRAM"
: > "$PGPASSFILE"
for r in postgres app teller_male teller_addu kyc1 auditor1; do
  pw=$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-24)
  q -d postgres -c "alter role $r password '$pw'" >/dev/null
  echo "*:$PORT:*:$r:$pw" >> "$PGPASSFILE"
done
ok "passwords in $PGPASSFILE"

log "TLS: a private CA and a server certificate for localhost"
openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj "/CN=pg-security-lab CA" \
  -keyout "$TLS/ca.key" -out "$TLS/ca.crt" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=localhost" -keyout "$TLS/server.key" -out "$TLS/server.csr" 2>/dev/null
printf 'subjectAltName = DNS:localhost, IP:127.0.0.1\nextendedKeyUsage = serverAuth\n' > "$TLS/server.ext"
openssl x509 -req -in "$TLS/server.csr" -CA "$TLS/ca.crt" -CAkey "$TLS/ca.key" -CAcreateserial \
  -days 365 -extfile "$TLS/server.ext" -out "$TLS/server.crt" 2>/dev/null
cp "$TLS/server.crt" "$TLS/server.key" "$DATA/"
ok "certificate: $(openssl x509 -in "$TLS/server.crt" -noout -text | grep -A1 'Subject Alternative Name' | tail -1 | xargs)"

log "server settings: TLS, pgaudit, connection logging"
cat >> "$DATA/postgresql.conf" <<'EOF'

# ---- hardening (scripts/02-harden.sh) ----
ssl = on
ssl_cert_file = 'server.crt'
ssl_key_file = 'server.key'
ssl_min_protocol_version = 'TLSv1.2'
shared_preload_libraries = 'pgaudit'
pgaudit.log = 'ddl, role'          # every schema change and every grant, role or password change
pgaudit.role = 'auditor'           # object audit: whatever auditor has rights on is logged
pgaudit.log_relation = on
pgaudit.log_parameter = off        # bind values can be customer data, keep them out of the log
log_connections = on
log_disconnections = on
EOF

log "pg_hba.conf: SCRAM everywhere, TLS for every TCP login"
cat > "$DATA/pg_hba.conf" <<'EOF'
# TYPE     DATABASE  USER  ADDRESS        METHOD
local      all       all                  scram-sha-256
hostssl    all       all   127.0.0.1/32   scram-sha-256
hostssl    all       all   ::1/128        scram-sha-256
hostnossl  all       all   all            reject
EOF

restart
q -c "create extension pgaudit"
ok "restarted with pgaudit $(q -c "select extversion from pg_extension where extname = 'pgaudit'")"

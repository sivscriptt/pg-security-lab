#!/usr/bin/env bash
# Build the "before" picture: a server set up the quick way, the way plenty of internal
# databases end up. Trust logins, MD5 passwords, no TLS, a superuser app account, and
# everyone allowed to do everything in the schema. Drops any existing lab.
source "$(dirname "$0")/lib.sh"
if is_up; then pg_ctl -D "$DATA" -m fast -w stop >/dev/null; fi
rm -rf "$LAB_DIR"; mkdir -p "$LAB_DIR/sock" "$LOGS"; chmod 700 "$LAB_DIR"

log "initdb with default trust auth"
initdb -D "$DATA" -U postgres --auth=trust >/dev/null 2>&1
cat >> "$DATA/postgresql.conf" <<EOF

# ---- pg-security-lab ----
port = $PORT
listen_addresses = 'localhost'
unix_socket_directories = '$LAB_DIR/sock'
shared_buffers = 128MB
password_encryption = md5
log_line_prefix = '%m [%p] %q%u@%d '
EOF
echo "host all all 127.0.0.1/32 trust" >> "$DATA/pg_hba.conf"
pg_ctl -D "$DATA" -l "$LOGS/postgres.log" -w start >/dev/null
q -d postgres -c "create database bank"

log "schema, data, and the bad habits"
q -f "$LAB_ROOT/sql/schema.sql" >/dev/null
q -f "$LAB_ROOT/sql/insecure.sql" >/dev/null
ok "running on port $PORT: $(q -c "select count(*) from core.customers") customers, $(q -c "select count(*) from core.accounts") accounts"

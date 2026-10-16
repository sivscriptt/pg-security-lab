#!/usr/bin/env bash
# The checklist reads settings. This script tries to get around them, as each user,
# over the network, and expects every attempt that should fail to fail.
source "$(dirname "$0")/lib.sh"
need_up
OUT="$RESULTS/prove.txt"; : > "$OUT"
PASS=0; FAIL=0
PII_KEY=$(cat "$LAB_DIR/keys/pii.key")

# tcp <user> [psql args]: TLS login over TCP, certificate checked against our CA
tcp() { local u=$1; shift
  psql -X -q -A -t -v ON_ERROR_STOP=1 "host=localhost port=$PORT dbname=bank user=$u sslmode=verify-full sslrootcert=$TLS/ca.crt" "$@" 2>&1; }

# check <title> <expected regex> <output>
check() {
  if echo "$3" | grep -qE "$2"; then PASS=$((PASS + 1)); m=PASS; c='1;32'; else FAIL=$((FAIL + 1)); m=FAIL; c='1;31'; fi
  local got; got=$( { echo "$3" | grep -oE "$2" | grep -v '^$' || echo "$3" | grep -v '^$' || true; } | head -1 | cut -c1-70)
  printf '%s  %-50s %s\n' "$m" "$1" "$got" >> "$OUT"
  printf '\033[%sm%s\033[0m  %-50s %s\n' "$c" "$m" "$1" "$got"
}
LOGSTART=$(wc -l < "$LOGS/postgres.log")

log "connections"
check "TCP without TLS is refused" "no encryption" \
  "$(psql -X "host=localhost port=$PORT dbname=bank user=app sslmode=disable" -c 'select 1' 2>&1)"
check "TLS with a verified certificate works" "TLSv1\.[23]" \
  "$(tcp app -c "select version || ' ' || cipher from pg_stat_ssl where pid = pg_backend_pid()")"
check "A wrong password is refused" "password authentication failed" \
  "$(PGPASSFILE=/dev/null PGPASSWORD=wrong psql -X "host=localhost port=$PORT dbname=bank user=app sslmode=require" -c 'select 1' 2>&1)"

log "tellers"
check "teller_male sees only branch 1" "^1\|2000$" \
  "$(tcp teller_male -c "select string_agg(distinct branch_id::text, ',') || '|' || count(*) from core.customers")"
check "teller_addu sees only branch 3" "^3\|2000$" \
  "$(tcp teller_addu -c "select string_agg(distinct branch_id::text, ',') || '|' || count(*) from core.customers")"
check "A teller can't read the encrypted ID column" "permission denied" \
  "$(tcp teller_male -c "select national_id_enc from core.customers limit 1")"
check "A teller finds a customer by ID in their branch" "^5$" \
  "$(tcp teller_male -c "select core.find_customer('A100005')")"
check "...but not a customer of another branch" "^$" \
  "$(tcp teller_addu -c "select coalesce(core.find_customer('A100005')::text, '')")"
check "A teller can't decrypt an ID" "permission denied" \
  "$(tcp teller_male -c "select core.reveal_national_id(5, 'x', 'curious')")"

log "KYC"
check "kyc1 can reveal an ID with the key and a reason" "^A100005$" \
  "$(tcp kyc1 -c "select core.reveal_national_id(5, '$PII_KEY', 'account opening check')")"
check "...and the look is logged in audit.pii_access" "^kyc1\|5\|account opening check$" \
  "$(tcp auditor1 -c "select db_user || '|' || customer_id || '|' || reason from audit.pii_access order by id desc limit 1")"
check "kyc1 can't reveal without a reason" "a reason is required" \
  "$(tcp kyc1 -c "select core.reveal_national_id(5, '$PII_KEY', '')")"
check "The wrong key gives an error, not data" "Wrong key or corrupt data" \
  "$(tcp kyc1 -c "select core.reveal_national_id(5, 'not-the-key', 'testing')")"

log "application"
check "app moves money through core.transfer" "^ok$" \
  "$(tcp app -c "select core.transfer(1, 2, 10)" -c "select 'ok'")"
check "app can't UPDATE balances directly" "permission denied" \
  "$(tcp app -c "update core.accounts set balance = 1000000 where id = 1")"
check "The transfer left two rows in the change log" "^2\|app$" \
  "$(tcp auditor1 -c "select count(*) || '|' || min(db_user) from audit.change_log where at > now() - interval '1 minute'")"
check "app can't touch the change log" "permission denied" \
  "$(tcp app -c "delete from audit.change_log")"
check "Even audit can't edit the change log" "permission denied" \
  "$(tcp auditor1 -c "delete from audit.change_log")"
check "app can't create objects in core" "permission denied" \
  "$(tcp app -c "create table core.backdoor (x int)")"
check "app is not a superuser" "^f$" \
  "$(tcp app -c "select rolsuper from pg_roles where rolname = current_user")"

log "pgaudit"
q -c "create table core.tmp_audit_demo (x int)" -c "drop table core.tmp_audit_demo" \
  -c "create role tmp_pw_demo login password 'Demo-Secret-123'" -c "drop role tmp_pw_demo"
sleep 1
NEWLOG=$(tail -n +"$((LOGSTART + 1))" "$LOGS/postgres.log")
echo "$NEWLOG" | grep 'AUDIT:' > "$RESULTS/pgaudit-sample.log" || true
check "DDL by postgres is in the audit log" "AUDIT: SESSION,[0-9]+,[0-9]+,DDL,CREATE TABLE" "$NEWLOG"
check "Role changes are in the audit log" "AUDIT: SESSION,[0-9]+,[0-9]+,ROLE,CREATE ROLE" "$NEWLOG"
check "A teller reading customers is in the audit log" "teller_male@bank LOG:  AUDIT: OBJECT,[0-9]+,[0-9]+,READ,SELECT,TABLE,core.customers" "$NEWLOG"
check "The password in CREATE ROLE is redacted" "password <REDACTED>" "$(echo "$NEWLOG" | grep 'tmp_pw_demo')"
check "...and the secret appears nowhere in the log" "^$" "$(echo "$NEWLOG" | grep 'Demo-Secret-123' || true)"

echo "$PASS passed, $FAIL failed" | tee -a "$OUT"
[ "$FAIL" = 0 ]

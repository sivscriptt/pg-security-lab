#!/usr/bin/env bash
# Shared helpers. Sourced, never run directly. Works on the bash 3.2 that ships with macOS.
set -euo pipefail

LAB_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=../lab.env
source "$LAB_ROOT/lab.env"

export PATH="$PGBIN:$PATH"
export PGHOST="$LAB_DIR/sock"
export PGPORT="$PORT"
export PGUSER=postgres
export PGDATABASE=bank
export PGPASSFILE="$LAB_DIR/.pgpass"      # written by 02-harden.sh, mode 600
export PGOPTIONS="-c client_min_messages=warning"

DATA="$LAB_DIR/data"
LOGS="$LAB_DIR/logs"
TLS="$LAB_DIR/tls"
RESULTS="$LAB_ROOT/results"

log()  { printf '\033[1;34m[%s]\033[0m %s\n' "$(date +%H:%M:%S)" "$*"; }
ok()   { printf '\033[1;32m  ok\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m  !!\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m  FAIL %s\033[0m\n' "$*" >&2; exit 1; }

# q [psql args...]: unaligned, tuples only, stop on first error.
q() { psql -X -q -A -t -v ON_ERROR_STOP=1 "$@"; }

is_up() { pg_isready -q >/dev/null 2>&1; }
need_up() { is_up || die "the lab isn't running (scripts/01-init.sh)"; }
restart() { pg_ctl -D "$DATA" -l "$LOGS/postgres.log" -m fast -w restart >/dev/null; }

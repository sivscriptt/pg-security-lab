#!/usr/bin/env bash
# Stop the instance and delete its folder, including certs, keys and passwords.
source "$(dirname "$0")/lib.sh"
is_up && pg_ctl -D "$DATA" -m fast -w stop >/dev/null && ok "stopped"
rm -rf "$LAB_DIR" && ok "removed $LAB_DIR"

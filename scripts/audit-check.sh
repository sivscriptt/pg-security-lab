#!/usr/bin/env bash
# Run the security checklist and print PASS / FAIL per item.
#   scripts/audit-check.sh [label]     saves a copy to results/check-<label>.txt
# Exits 1 if anything fails, so it can gate a pipeline.
source "$(dirname "$0")/lib.sh"
need_up
LABEL=${1:-latest}; OUT="$RESULTS/check-$LABEL.txt"; mkdir -p "$RESULTS"

ROWS=$(q -F '|' -f "$LAB_ROOT/sql/audit-checks.sql")
PASS=0; FAIL=0; : > "$OUT"
while IFS='|' read -r id title pass detail; do
  if [ "$pass" = t ]; then PASS=$((PASS + 1)); mark="PASS"; color='1;32'
  else FAIL=$((FAIL + 1)); mark="FAIL"; color='1;31'; fi
  printf '%s  %s  %-52s %s\n' "$id" "$mark" "$title" "$detail" >> "$OUT"
  printf '%s  \033[%sm%s\033[0m  %-52s %s\n' "$id" "$color" "$mark" "$title" "$detail"
done <<< "$ROWS"
echo "$PASS passed, $FAIL failed" | tee -a "$OUT"
[ "$FAIL" = 0 ]

#!/usr/bin/env bash
# tests/security/scenarios/s04c_slow_signups.sh
#
# S-04c — Slow distributed signups
# OWASP:  OAT-019 variant
# Tool:   curl + sleep
#
# Use case:
#   Actor:        Patient bot creating accounts at human-like intervals
#   Goal:         Slip past velocity-based detection
#   Prereqs:      Time and willingness to wait
#   Threat model: Single-source; one signup every N seconds (mimics human rate)
#
# Pass criteria:
#   1. Even at human-like rate, behavior_class model recognizes the pattern
#      based on payload similarity (same phone prefix, same city, same password)
#   2. Detection within ≤8 slow signups
#   3. Containment for the rest

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/../lib/common.sh"

# Clear decoy engine state from prior scenarios (test isolation)
reset_decoy_state

SCENARIO_ID="s04c_slow_signups"
log "=== $SCENARIO_ID — Slow distributed signups ==="

REAL_BEFORE=$(sqlite3 "$DIGITAL_DB" "SELECT COUNT(*) FROM users;" 2>/dev/null || echo 0)
DECOY_BEFORE=$(sqlite3 "$DECOY_DB" "SELECT COUNT(*) FROM users;" 2>/dev/null || echo 0)

N_ATTEMPTS=8
SPACING=2  # seconds between signups; would be 60+ in real attack but compressed for test

ATTEMPT_LOG=$(mktemp)
SUCCESSES=0
FLAG_AT=0

log "Slow signups: $N_ATTEMPTS attempts @${SPACING}s spacing"

for i in $(seq 1 $N_ATTEMPTS); do
    EMAIL="slow_$(date +%s)_${i}@gmail.com"
    body="{
        \"full_name\":\"Slow User $i\",
        \"email\":\"$EMAIL\",
        \"password\":\"SlowPass2026!\",
        \"phone\":\"+966500222$(printf '%03d' $i)\",
        \"city\":\"Jeddah\"
    }"
    status=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
        "$PROXY_URL/api/v1/auth/sign-up" \
        -H "Content-Type: application/json" \
        -d "$body")
    echo "i=$i email=$EMAIL status=$status" >> "$ATTEMPT_LOG"

    if [[ "$status" =~ ^2 ]]; then SUCCESSES=$((SUCCESSES+1)); fi
    if [[ "$status" =~ ^(202|429|423)$ ]] && [ $FLAG_AT -eq 0 ]; then
        FLAG_AT=$i
    fi

    log "signup $i: status=$status"
    sleep $SPACING
done

REAL_AFTER=$(sqlite3 "$DIGITAL_DB" "SELECT COUNT(*) FROM users;" 2>/dev/null || echo 0)
DECOY_AFTER=$(sqlite3 "$DECOY_DB" "SELECT COUNT(*) FROM users;" 2>/dev/null || echo 0)
REAL_DELTA=$((REAL_AFTER - REAL_BEFORE))
DECOY_DELTA=$((DECOY_AFTER - DECOY_BEFORE))

log "Real delta: $REAL_DELTA, decoy delta: $DECOY_DELTA"
log "First flag at signup: $FLAG_AT"

STATUS="PASS"
NOTES=""
if [ $REAL_DELTA -ge $N_ATTEMPTS ]; then
    STATUS="FAIL"
    NOTES="slow pacing fully evaded detection — all $REAL_DELTA created in real DB"
elif [ $REAL_DELTA -gt 4 ]; then
    STATUS="PARTIAL"
    NOTES="$REAL_DELTA real DB users created (>4); slow pacing partially evaded"
fi

CONTAINMENT_PCT=$(python3 -c "
n = $N_ATTEMPTS
real = $REAL_DELTA
if n == 0:
    print(100)
else:
    print(round((1 - real/n) * 100, 1))
")

DETAIL=$(cat <<EOF
{
  "signup_attempts": $N_ATTEMPTS,
  "spacing_seconds": $SPACING,
  "real_db_users_added": $REAL_DELTA,
  "decoy_db_users_added": $DECOY_DELTA,
  "2xx_responses": $SUCCESSES,
  "first_flag_at_signup": $FLAG_AT,
  "containment_pct": "$CONTAINMENT_PCT",
  "notes": "$NOTES"
}
EOF
)

write_result "$SCENARIO_ID" "$STATUS" \
    "Slow signups: $N_ATTEMPTS @${SPACING}s, $REAL_DELTA real / $DECOY_DELTA decoy (${CONTAINMENT_PCT}% contained)" \
    "$DETAIL"

[ "$STATUS" = "PASS" ]

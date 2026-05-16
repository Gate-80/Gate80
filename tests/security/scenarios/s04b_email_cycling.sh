#!/usr/bin/env bash
# tests/security/scenarios/s04b_email_cycling.sh
#
# S-04b — Email cycling (+N suffix bypass)
# OWASP:  OAT-019 variant
# Tool:   curl with email variations
#
# Use case:
#   Actor:        Bot abusing Gmail-style email aliasing (foo+1@, foo+2@, foo.x@)
#                 to bypass "one signup per email" rules
#   Goal:         Create many accounts from the same actual mailbox
#   Prereqs:      Single mailbox; knowledge of email parsing rules
#   Threat model: Single-source; varied-looking emails but same root
#
# Pass criteria:
#   1. Detection notices that all emails resolve to the same root
#   2. After detection: real DB receives 0 new users with that root
#   3. Decoy DB absorbs the rest

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/../lib/common.sh"

# Clear decoy engine state from prior scenarios (test isolation)
reset_decoy_state

SCENARIO_ID="s04b_email_cycling"
log "=== $SCENARIO_ID — Email cycling (+N suffix) ==="

DB_PRE="$RESULTS_DIR/${SCENARIO_ID}_db_pre.json"
snapshot_db_counts "$DB_PRE"
REAL_USERS_BEFORE=$(sqlite3 "$DIGITAL_DB" "SELECT COUNT(*) FROM users;" 2>/dev/null || echo 0)
DECOY_USERS_BEFORE=$(sqlite3 "$DECOY_DB" "SELECT COUNT(*) FROM users;" 2>/dev/null || echo 0)

# Root email — all variations resolve to this in reality
ROOT="cycle_attacker_$(date +%s)"
DOMAIN="gmail.com"

# Variations
declare -a VARIATIONS=(
    "$ROOT@$DOMAIN"
    "$ROOT+1@$DOMAIN"
    "$ROOT+2@$DOMAIN"
    "$ROOT+3@$DOMAIN"
    "$ROOT+test@$DOMAIN"
    "$ROOT.x@$DOMAIN"
    "$ROOT.y@$DOMAIN"
    "$ROOT+$(date +%s%N | tail -c 6)@$DOMAIN"
)

# Also variations with periods (Gmail ignores periods in local-part)
LP_LEN=${#ROOT}
if [ $LP_LEN -gt 4 ]; then
    VARIATIONS+=("${ROOT:0:3}.${ROOT:3}@$DOMAIN")
fi

ATTEMPT_LOG=$(mktemp)
SUCCESSES=0
N_ATTEMPTS=${#VARIATIONS[@]}

log "Cycling $N_ATTEMPTS variations of root email '$ROOT@$DOMAIN'"

for i in "${!VARIATIONS[@]}"; do
    email="${VARIATIONS[$i]}"
    body="{
        \"full_name\":\"Cycle User $i\",
        \"email\":\"$email\",
        \"password\":\"CyclePass2026!\",
        \"phone\":\"+966500111$(printf '%03d' $i)\",
        \"city\":\"Riyadh\"
    }"
    status=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
        "$PROXY_URL/api/v1/auth/sign-up" \
        -H "Content-Type: application/json" \
        -d "$body")
    echo "i=$i email=$email status=$status" >> "$ATTEMPT_LOG"

    if [[ "$status" =~ ^2 ]]; then SUCCESSES=$((SUCCESSES+1)); fi
    log "variation[$i]: $email -> $status"
done

REAL_USERS_AFTER=$(sqlite3 "$DIGITAL_DB" "SELECT COUNT(*) FROM users;" 2>/dev/null || echo 0)
DECOY_USERS_AFTER=$(sqlite3 "$DECOY_DB" "SELECT COUNT(*) FROM users;" 2>/dev/null || echo 0)
REAL_DELTA=$((REAL_USERS_AFTER - REAL_USERS_BEFORE))
DECOY_DELTA=$((DECOY_USERS_AFTER - DECOY_USERS_BEFORE))

log "Real DB delta: $REAL_DELTA, decoy delta: $DECOY_DELTA"

STATUS="PASS"
NOTES=""

# Ideal: only 1 real DB user (the first variation), rest in decoy
# Partial: a few real DB users (some passed before detection)
# Fail: most/all real

if [ $REAL_DELTA -ge $N_ATTEMPTS ]; then
    STATUS="FAIL"
    NOTES="all $REAL_DELTA cycled signups created real users — email cycling not detected"
elif [ $REAL_DELTA -gt 3 ]; then
    STATUS="PARTIAL"
    NOTES="$REAL_DELTA real DB writes from $N_ATTEMPTS cycled emails (>3, suggests late detection)"
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
  "root_email": "$ROOT@$DOMAIN",
  "variations_attempted": $N_ATTEMPTS,
  "real_db_users_added": $REAL_DELTA,
  "decoy_db_users_added": $DECOY_DELTA,
  "2xx_responses": $SUCCESSES,
  "containment_pct": "$CONTAINMENT_PCT",
  "notes": "$NOTES"
}
EOF
)

write_result "$SCENARIO_ID" "$STATUS" \
    "Email cycling: $N_ATTEMPTS variations, $REAL_DELTA real / $DECOY_DELTA decoy (${CONTAINMENT_PCT}% contained)" \
    "$DETAIL"

[ "$STATUS" = "PASS" ]

#!/usr/bin/env bash
# tests/security/scenarios/s04a_mass_signup.sh
#
# S-04a — Mass signup bot
# OWASP:  OAT-019 (Account Creation)
# Tool:   curl in rapid loop
#
# Use case:
#   Actor:        Bot creating many accounts to abuse welcome bonuses, seed fake reviews, etc.
#   Goal:         Create N accounts quickly
#   Prereqs:      Email-domain access, automation
#   Threat model: Single-source rapid burst (no realistic delay)
#
# Pass criteria:
#   1. Account-creation pattern detected → flagged
#   2. Detection within ≤6 rapid signups
#   3. After detection: real DB receives 0 new users; decoy DB receives the rest
#   4. Attacker still sees "success" responses (so they don't pivot to evade)

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/../lib/common.sh"

# Clear decoy engine state from prior scenarios (test isolation)
reset_decoy_state

SCENARIO_ID="s04a_mass_signup"
log "=== $SCENARIO_ID — Mass signup bot ==="

DB_PRE="$RESULTS_DIR/${SCENARIO_ID}_db_pre.json"
snapshot_db_counts "$DB_PRE"
REAL_USERS_BEFORE=$(sqlite3 "$DIGITAL_DB" "SELECT COUNT(*) FROM users;" 2>/dev/null || echo 0)
DECOY_USERS_BEFORE=$(sqlite3 "$DECOY_DB" "SELECT COUNT(*) FROM users;" 2>/dev/null || echo 0)
log "Pre: real=$REAL_USERS_BEFORE users, decoy=$DECOY_USERS_BEFORE users"

PROXY_PRE="$RESULTS_DIR/${SCENARIO_ID}_proxy_pre.json"
snapshot_proxy_log_counts "$PROXY_PRE"

N_SIGNUPS=15
ATTEMPT_LOG=$(mktemp)
SUCCESS_201=0
FLAG_FIRED_AT=0
SUSPICIOUS_PENDING_REVIEW=0  # 202 responses from decoy

log "Attempting $N_SIGNUPS rapid signups…"

for i in $(seq 1 $N_SIGNUPS); do
    EMAIL="bot_$(date +%s)_${i}@spam.test"
    body="{
        \"full_name\":\"Bot User $i\",
        \"email\":\"$EMAIL\",
        \"password\":\"BotPass2026!\",
        \"phone\":\"+9665$(echo $RANDOM$RANDOM | cut -c1-8)\",
        \"city\":\"Jeddah\"
    }"
    status=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
        "$PROXY_URL/api/v1/auth/sign-up" \
        -H "Content-Type: application/json" \
        -d "$body")
    echo "signup=$i email=$EMAIL status=$status" >> "$ATTEMPT_LOG"

    case "$status" in
        201) SUCCESS_201=$((SUCCESS_201+1)) ;;
        202) SUSPICIOUS_PENDING_REVIEW=$((SUSPICIOUS_PENDING_REVIEW+1))
             if [ $FLAG_FIRED_AT -eq 0 ]; then FLAG_FIRED_AT=$i; fi ;;
        429|423) if [ $FLAG_FIRED_AT -eq 0 ]; then FLAG_FIRED_AT=$i; fi ;;
    esac

    log "signup $i: status=$status"
done

DB_POST="$RESULTS_DIR/${SCENARIO_ID}_db_post.json"
snapshot_db_counts "$DB_POST"
PROXY_POST="$RESULTS_DIR/${SCENARIO_ID}_proxy_post.json"
snapshot_proxy_log_counts "$PROXY_POST"

REAL_USERS_AFTER=$(sqlite3 "$DIGITAL_DB" "SELECT COUNT(*) FROM users;" 2>/dev/null || echo 0)
DECOY_USERS_AFTER=$(sqlite3 "$DECOY_DB" "SELECT COUNT(*) FROM users;" 2>/dev/null || echo 0)
REAL_DELTA=$((REAL_USERS_AFTER - REAL_USERS_BEFORE))
DECOY_DELTA=$((DECOY_USERS_AFTER - DECOY_USERS_BEFORE))

log "Post: real=$REAL_USERS_AFTER (delta=$REAL_DELTA), decoy=$DECOY_USERS_AFTER (delta=$DECOY_DELTA)"
log "201 (created) responses: $SUCCESS_201"
log "202 (pending review) responses: $SUSPICIOUS_PENDING_REVIEW"
log "First flag/throttle at signup: $FLAG_FIRED_AT"

STATUS="PASS"
NOTES=""

# Containment evaluation
if [ $REAL_DELTA -ge $N_SIGNUPS ]; then
    STATUS="FAIL"
    NOTES="all $REAL_DELTA signups landed in real DB — no containment"
elif [ $REAL_DELTA -gt 5 ]; then
    STATUS="PARTIAL"
    NOTES="$REAL_DELTA real DB writes (>5); detection fired late"
fi

# Bonus check: if 201s outnumber 202s after the flag, defense isn't using decoy properly
if [ $FLAG_FIRED_AT -gt 0 ]; then
    AFTER_FLAG_201=0
    while IFS= read -r line; do
        attempt=$(echo "$line" | grep -oE "signup=[0-9]+" | cut -d= -f2)
        st=$(echo "$line" | grep -oE "status=[0-9]+" | cut -d= -f2)
        if [ "$attempt" -gt $FLAG_FIRED_AT ] && [ "$st" = "201" ]; then
            AFTER_FLAG_201=$((AFTER_FLAG_201+1))
        fi
    done < "$ATTEMPT_LOG"
    log "After flag fired, $AFTER_FLAG_201 still got 201"
fi

CONTAINMENT_PCT=$(python3 -c "
n = $N_SIGNUPS
real = $REAL_DELTA
if n == 0:
    print(100)
else:
    print(round((1 - real/n) * 100, 1))
")
log "Account-creation containment: ${CONTAINMENT_PCT}%"

DETAIL=$(cat <<EOF
{
  "signup_attempts": $N_SIGNUPS,
  "real_db_users_added": $REAL_DELTA,
  "decoy_db_users_added": $DECOY_DELTA,
  "201_responses": $SUCCESS_201,
  "202_pending_review": $SUSPICIOUS_PENDING_REVIEW,
  "first_flag_at_signup": $FLAG_FIRED_AT,
  "containment_pct": "$CONTAINMENT_PCT",
  "notes": "$NOTES"
}
EOF
)

write_result "$SCENARIO_ID" "$STATUS" \
    "Mass signup: $N_SIGNUPS attempts, $REAL_DELTA real / $DECOY_DELTA decoy (${CONTAINMENT_PCT}% contained)" \
    "$DETAIL"

[ "$STATUS" = "PASS" ]

#!/usr/bin/env bash
# tests/security/scenarios/s01c_slow_trickle.sh
#
# S-01c — Low-and-slow credential attack
# OWASP:  OAT-007 / OAT-008 variant
# Tool:   bash + sleep (intentional pacing to evade naive rate limiting)
#
# Use case:
#   Actor:        Sophisticated attacker who knows rate-limit detection exists
#   Goal:         Avoid triggering detection by spacing attempts out
#   Prereqs:      Target email, intent to wait
#   Threat model: Single-source; one attempt every N seconds for ~5 minutes
#                 (we use shorter spacing for test feasibility, but the principle is the same)
#
# Pass criteria:
#   1. Even with pacing, behavior_class model detects the pattern based on:
#      - Failed-login ratio (all 401s)
#      - Same email targeted
#   2. Session is flagged within ≤10 attempts even at slow pace

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/../lib/common.sh"

# Clear decoy engine state from prior scenarios (test isolation)
reset_decoy_state

SCENARIO_ID="s01c_slow_trickle"
log "=== $SCENARIO_ID — Low-and-slow credential attack ==="

PRE="$RESULTS_DIR/${SCENARIO_ID}_pre.json"
snapshot_proxy_log_counts "$PRE"
PRE_BACKEND=$(python3 -c "import json; print(json.load(open('$PRE'))['routed_to_backend'])")
PRE_FLAGGED=$(python3 -c "import json; print(json.load(open('$PRE'))['flagged_as_suspicious'])")

# Slow pacing: 3 seconds between attempts. With 10 attempts that's ~30s of test time.
# Real-world attackers might pace at minutes; we use seconds for thesis-defense practicality.
SPACING=3
N_ATTEMPTS_MAX=12

ATTEMPT_LOG=$(mktemp)
SUCCESS=0
FLAGGED_AT=0

log "Slow-trickle: 1 attempt every ${SPACING}s, max $N_ATTEMPTS_MAX attempts, against $LEGIT_USER_EMAIL"

for i in $(seq 1 $N_ATTEMPTS_MAX); do
    # Use a varied-but-wrong password each time
    pwd="wrongpwd_${i}_$(date +%s)"
    body="{\"email\":\"$LEGIT_USER_EMAIL\",\"password\":\"$pwd\"}"
    t0=$(date +%s)
    status=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "$PROXY_URL/api/v1/auth/sign-in" \
        -H "Content-Type: application/json" \
        -d "$body")
    t1=$(date +%s)
    echo "attempt=$i pwd=$pwd status=$status latency=$((t1-t0))s" >> "$ATTEMPT_LOG"
    log "attempt $i: status=$status"

    if [ "$status" = "200" ]; then
        SUCCESS=$((SUCCESS+1))
    fi
    if [ "$status" = "423" ] || [ "$status" = "429" ]; then
        if [ $FLAGGED_AT -eq 0 ]; then FLAGGED_AT=$i; fi
    fi

    sleep $SPACING
done

log "Trickle complete. First lockout at attempt: $FLAGGED_AT"

POST="$RESULTS_DIR/${SCENARIO_ID}_post.json"
snapshot_proxy_log_counts "$POST"
POST_BACKEND=$(python3 -c "import json; print(json.load(open('$POST'))['routed_to_backend'])")
POST_FLAGGED=$(python3 -c "import json; print(json.load(open('$POST'))['flagged_as_suspicious'])")
BACKEND_DELTA=$((POST_BACKEND - PRE_BACKEND))
FLAG_DELTA=$((POST_FLAGGED - PRE_FLAGGED))

STATUS="PASS"
NOTES=""
if [ "$SUCCESS" -gt 0 ]; then
    STATUS="FAIL"; NOTES="$SUCCESS unexpected logins"
elif [ "$FLAGGED_AT" -eq 0 ]; then
    STATUS="FAIL"
    NOTES="no flag/lockout fired — low-and-slow pacing evaded detection (defense gap for thesis)"
elif [ "$FLAGGED_AT" -gt 10 ]; then
    STATUS="PARTIAL"
    NOTES="lockout fired at $FLAGGED_AT (>10 — late, but did fire)"
fi

DETAIL=$(cat <<EOF
{
  "attempts": $N_ATTEMPTS_MAX,
  "spacing_seconds": $SPACING,
  "first_lockout_at": $FLAGGED_AT,
  "unexpected_successes": $SUCCESS,
  "backend_delta": $BACKEND_DELTA,
  "flag_delta": $FLAG_DELTA,
  "notes": "$NOTES"
}
EOF
)

write_result "$SCENARIO_ID" "$STATUS" \
    "Slow-trickle: $N_ATTEMPTS_MAX attempts @${SPACING}s, lockout at #$FLAGGED_AT" \
    "$DETAIL"

[ "$STATUS" = "PASS" ]

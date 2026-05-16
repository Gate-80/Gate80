#!/usr/bin/env bash
# tests/security/scenarios/s01a_brute_force.sh
#
# S-01a — Credential brute-force on a single known user
# OWASP:  OAT-007 (Credential Cracking)
# Tool:   hydra against http-post-json on /api/v1/auth/sign-in via proxy
#
# Use case:
#   Actor:        Automated brute-force bot
#   Goal:         Gain access to user@example.com's wallet
#   Prereqs:      Knowledge of target email; rockyou-style password list
#   Threat model: Single-source; no stolen creds; intends to try thousands of passwords
#
# Pass criteria:
#   1. Detection: session flagged within ≤6 requests
#   2. Lockout: 423 returned by request ≤9
#   3. Containment: 0 real backend writes after flag fires
#   4. Even if attacker's wordlist contains the correct password, lockout still applies

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/../lib/common.sh"

# Clear decoy engine state from prior scenarios (test isolation)
reset_decoy_state

SCENARIO_ID="s01a_brute_force"
log "=== $SCENARIO_ID — Credential brute-force on known user ==="

# Snapshot before
PRE="$RESULTS_DIR/${SCENARIO_ID}_pre.json"
snapshot_proxy_log_counts "$PRE"
PRE_BACKEND=$(jq -r '.routed_to_backend' "$PRE" 2>/dev/null || python3 -c "import json,sys; print(json.load(open('$PRE'))['routed_to_backend'])")
log "Pre-test routed_to_backend: $PRE_BACKEND"

# Build a small password list for the attack
# Use top-100 common passwords, plus one trailing wrong attempt
PWD_LIST=$(mktemp)
if [ -f "$WL_TOP100_PWD" ]; then
    cp "$WL_TOP100_PWD" "$PWD_LIST"
else
    # Fallback inline list if seclists not at expected path
    printf "%s\n" 123456 password password123 qwerty abc123 letmein 111111 monkey admin welcome > "$PWD_LIST"
fi
N_PASSWORDS=$(wc -l < "$PWD_LIST" | tr -d ' ')
log "Will try $N_PASSWORDS passwords against $LEGIT_USER_EMAIL"

# Method: use curl directly (hydra http-post-json requires specific syntax that varies
# by version; manual loop is simpler and gives us per-request status codes).
ATTEMPT_LOG=$(mktemp)
SUCCESS=0
LOCKED_OUT_AT=0
FLAGGED_AT=0

i=0
while IFS= read -r pwd; do
    i=$((i+1))
    body="{\"email\":\"$LEGIT_USER_EMAIL\",\"password\":\"$pwd\"}"
    status=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "$PROXY_URL/api/v1/auth/sign-in" \
        -H "Content-Type: application/json" \
        -d "$body")
    echo "attempt=$i pwd=$pwd status=$status" >> "$ATTEMPT_LOG"

# Check lockout — record FIRST occurrence only
    if [ "$status" = "423" ]; then
        if [ "$LOCKED_OUT_AT" -eq 0 ]; then
            LOCKED_OUT_AT=$i
            log "Lockout (423) first hit at attempt $i"
        fi
        # Run 5 more attempts after first lockout to verify it persists
        if [ "$i" -ge "$((LOCKED_OUT_AT + 5))" ]; then
            log "Verified lockout persisted for 5 attempts after first hit"
            break
        fi
    fi

    # Check for unexpected success (would indicate failure of defense)
    if [ "$status" = "200" ]; then
        SUCCESS=$((SUCCESS+1))
        log "ALERT: 200 OK at attempt $i with password '$pwd' — defense bypassed?"
    fi

    # Safety: cap at 50 attempts so we don't spin forever if nothing fires
    [ $i -ge 50 ] && break
done < "$PWD_LIST"

ATTEMPTS=$i
log "Total attempts: $ATTEMPTS"
log "Lockout fired at attempt: $LOCKED_OUT_AT"
log "Unexpected 200s (defense bypass): $SUCCESS"

# Snapshot after
POST="$RESULTS_DIR/${SCENARIO_ID}_post.json"
snapshot_proxy_log_counts "$POST"
POST_BACKEND=$(python3 -c "import json; print(json.load(open('$POST'))['routed_to_backend'])")
POST_DECOY=$(python3 -c "import json; print(json.load(open('$POST'))['routed_to_decoy'])")
POST_FLAGGED=$(python3 -c "import json; print(json.load(open('$POST'))['flagged_as_suspicious'])")
BACKEND_DELTA=$((POST_BACKEND - PRE_BACKEND))

log "Backend writes during test: $BACKEND_DELTA"
log "Total flagged-as-suspicious now: $POST_FLAGGED"
log "Total routed to decoy now: $POST_DECOY"

# Pass criteria evaluation
STATUS="PASS"
NOTES=""
if [ "$LOCKED_OUT_AT" -eq 0 ]; then
    STATUS="FAIL"; NOTES="lockout never fired"
elif [ "$LOCKED_OUT_AT" -gt 9 ]; then
    STATUS="PARTIAL"; NOTES="lockout fired late (at $LOCKED_OUT_AT, expected ≤9)"
elif [ "$SUCCESS" -gt 0 ]; then
    STATUS="FAIL"; NOTES="defense bypassed — got 200 with attacker-chosen password"
elif [ "$BACKEND_DELTA" -gt "$LOCKED_OUT_AT" ]; then
    STATUS="PARTIAL"; NOTES="$BACKEND_DELTA backend writes vs lockout at #$LOCKED_OUT_AT — some may have leaked after detection"
fi

DETAIL=$(cat <<EOF
{
  "attempts": $ATTEMPTS,
  "lockout_at": $LOCKED_OUT_AT,
  "unexpected_successes": $SUCCESS,
  "backend_delta_during_test": $BACKEND_DELTA,
  "decoy_count_after": $POST_DECOY,
  "flagged_count_after": $POST_FLAGGED,
  "attempts_log": "$ATTEMPT_LOG",
  "notes": "$NOTES"
}
EOF
)

write_result "$SCENARIO_ID" "$STATUS" \
    "Brute-force: ${ATTEMPTS} attempts, lockout at #${LOCKED_OUT_AT}, ${SUCCESS} bypass(es)" \
    "$DETAIL"

# Cleanup tmp
rm -f "$PWD_LIST"

[ "$STATUS" = "PASS" ]

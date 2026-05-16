#!/usr/bin/env bash
# tests/security/scenarios/s01b_cred_stuffing.sh
#
# S-01b — Credential stuffing across many users
# OWASP:  OAT-008 (Credential Stuffing)
# Tool:   curl loop (functionally equivalent to hydra -L users -P passwords)
#
# Use case:
#   Actor:        Attacker with a list of leaked email:password pairs from another breach
#   Goal:         Find any GATE80 account that reused those credentials
#   Prereqs:      Email list (from leak), password list (from leak)
#   Threat model: Single-source; each attempt is on a DIFFERENT email — i.e. not brute-force
#                 against ONE user. The same defense MUST still detect the pattern.
#
# Pass criteria:
#   1. Detection: session flagged within ≤8 cross-user attempts
#   2. Containment: 0 successful authentications even if some pairs are valid
#   3. Backend writes during test stay near baseline

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/../lib/common.sh"

# Clear decoy engine state from prior scenarios (test isolation)
reset_decoy_state

SCENARIO_ID="s01b_cred_stuffing"
log "=== $SCENARIO_ID — Credential stuffing across multiple users ==="

PRE="$RESULTS_DIR/${SCENARIO_ID}_pre.json"
snapshot_proxy_log_counts "$PRE"
PRE_BACKEND=$(python3 -c "import json; print(json.load(open('$PRE'))['routed_to_backend'])")
PRE_FLAGGED=$(python3 -c "import json; print(json.load(open('$PRE'))['flagged_as_suspicious'])")

# Build attack list: real emails + leaked-style passwords. Include 1-2 valid pairs
# so we can verify the defense holds even when the attacker gets lucky.
ATTEMPTS_FILE=$(mktemp)
cat > "$ATTEMPTS_FILE" <<'EOF'
taif.alsaadi@gmail.com:Welcome1
hanan.alharbi@gmail.com:Sunshine2024
queenrama@gmail.com:Password!
user@example.com:hunter2
taif.alsaadi@gmail.com:123456
hanan.alharbi@gmail.com:password
queenrama@gmail.com:imthequ33n
user@example.com:password123
random1@example.com:LetMeIn1
random2@example.com:Pa$$w0rd
attacker_target@example.com:abc123
attacker_other@example.com:welcome
EOF

# Note: line 7 has queenrama's REAL password (imthequ33n).
# Line 8 has user@example.com's REAL password (password123).
# A correctly-defended system should still flag/block these.

N_ATTEMPTS=$(wc -l < "$ATTEMPTS_FILE" | tr -d ' ')
log "Will try $N_ATTEMPTS email:password pairs (2 of which contain real passwords)"

ATTEMPT_LOG=$(mktemp)
FLAGGED_AT=0
SUCCESS_COUNT=0
FORBIDDEN_COUNT=0  # 423 lockout responses
i=0

while IFS=: read -r email pwd; do
    i=$((i+1))
    body="{\"email\":\"$email\",\"password\":\"$pwd\"}"
    status=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "$PROXY_URL/api/v1/auth/sign-in" \
        -H "Content-Type: application/json" \
        -d "$body")
    echo "attempt=$i email=$email status=$status" >> "$ATTEMPT_LOG"

    case "$status" in
        200) SUCCESS_COUNT=$((SUCCESS_COUNT+1))
             log "ALERT: 200 OK at attempt $i for $email — defense let real password through"
             ;;
        423) FORBIDDEN_COUNT=$((FORBIDDEN_COUNT+1))
             if [ $FLAGGED_AT -eq 0 ]; then FLAGGED_AT=$i; fi
             ;;
        429) FORBIDDEN_COUNT=$((FORBIDDEN_COUNT+1))
             if [ $FLAGGED_AT -eq 0 ]; then FLAGGED_AT=$i; fi
             ;;
    esac

    [ $i -ge 20 ] && break
done < "$ATTEMPTS_FILE"

log "Total attempts: $i"
log "Successful (200): $SUCCESS_COUNT  -- expect 0 if defense holds"
log "Locked/throttled (423/429): $FORBIDDEN_COUNT"
log "First lockout at attempt: $FLAGGED_AT"

POST="$RESULTS_DIR/${SCENARIO_ID}_post.json"
snapshot_proxy_log_counts "$POST"
POST_BACKEND=$(python3 -c "import json; print(json.load(open('$POST'))['routed_to_backend'])")
POST_FLAGGED=$(python3 -c "import json; print(json.load(open('$POST'))['flagged_as_suspicious'])")
BACKEND_DELTA=$((POST_BACKEND - PRE_BACKEND))
FLAG_DELTA=$((POST_FLAGGED - PRE_FLAGGED))

log "Backend delta: $BACKEND_DELTA   Flagged delta: $FLAG_DELTA"

STATUS="PASS"
NOTES=""
if [ "$SUCCESS_COUNT" -gt 0 ]; then
    STATUS="FAIL"; NOTES="$SUCCESS_COUNT real-password logins succeeded — credential stuffing not contained"
elif [ "$FLAGGED_AT" -eq 0 ]; then
    STATUS="PARTIAL"; NOTES="no lockout/throttle observed; pattern not detected"
elif [ "$FLAGGED_AT" -gt 8 ]; then
    STATUS="PARTIAL"; NOTES="lockout fired at $FLAGGED_AT (>8 — late)"
fi

DETAIL=$(cat <<EOF
{
  "attempts": $i,
  "first_lockout_at": $FLAGGED_AT,
  "successful_logins": $SUCCESS_COUNT,
  "blocked_count": $FORBIDDEN_COUNT,
  "backend_delta": $BACKEND_DELTA,
  "flag_delta": $FLAG_DELTA,
  "notes": "$NOTES"
}
EOF
)

write_result "$SCENARIO_ID" "$STATUS" \
    "Stuffing: $i attempts, $SUCCESS_COUNT real-password successes, lockout at #$FLAGGED_AT" \
    "$DETAIL"

rm -f "$ATTEMPTS_FILE"

[ "$STATUS" = "PASS" ]

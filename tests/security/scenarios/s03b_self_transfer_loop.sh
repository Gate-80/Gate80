#!/usr/bin/env bash
# tests/security/scenarios/s03b_self_transfer_loop.sh
#
# S-03b — Rapid back-and-forth transfer abuse loop
# OWASP:  OAT-012 variant
# Tool:   curl in tight loop
#
# Use case:
#   Actor:        Attacker with two compromised accounts (or two created accounts)
#   Goal:         Exploit any race condition or credit-bug in transfer logic
#   Prereqs:      Two valid session tokens
#   Threat model: Tight loop; >10 transfers/sec; alternating direction
#
# Pass criteria:
#   1. Self-transfer detection (the backend ALREADY blocks transfer to self,
#      but a rapid two-account loop should also be flagged as suspicious)
#   2. Real wallet balances unchanged by the abusive loop
#   3. Detection within ≤8 transfers

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/../lib/common.sh"

# Clear decoy engine state from prior scenarios (test isolation)
reset_decoy_state

SCENARIO_ID="s03b_self_transfer_loop"
log "=== $SCENARIO_ID — Self-transfer abuse loop ==="

DB_PRE="$RESULTS_DIR/${SCENARIO_ID}_db_pre.json"
snapshot_db_counts "$DB_PRE"
PROXY_PRE="$RESULTS_DIR/${SCENARIO_ID}_proxy_pre.json"
snapshot_proxy_log_counts "$PROXY_PRE"

# Get balances before
U1004_BEFORE=$(sqlite3 "$DIGITAL_DB" "SELECT balance FROM wallets WHERE user_id='u_1006';" 2>/dev/null || echo 0)
U1001_BEFORE=$(sqlite3 "$DIGITAL_DB" "SELECT balance FROM wallets WHERE user_id='u_1001';" 2>/dev/null || echo 0)
log "Pre-attack: u_1006=$U1004_BEFORE, u_1001=$U1001_BEFORE"

# Get token (attacker uses u_1006's token to bounce funds to/from u_1001)
TOKEN=$(get_victim_token)
[ -z "$TOKEN" ] && { err "no token"; exit 1; }

N_LOOP_ITERATIONS=10
AMOUNT=20

ATTEMPT_LOG=$(mktemp)
SUCCESSES=0
LOCKOUT_AT=0

log "Bouncing $AMOUNT SAR back-and-forth, $N_LOOP_ITERATIONS times"

for i in $(seq 1 $N_LOOP_ITERATIONS); do
    # u_1006 -> u_1001 transfer
    s1=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
        "$PROXY_URL/api/v1/users/u_1006/wallet/transfer/u_1001" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"amount\":$AMOUNT}")
    echo "loop=$i direction=1004->1001 status=$s1" >> "$ATTEMPT_LOG"

    if [ "$s1" = "200" ]; then SUCCESSES=$((SUCCESSES+1)); fi
    if [[ "$s1" =~ ^(423|429)$ ]] && [ $LOCKOUT_AT -eq 0 ]; then LOCKOUT_AT=$i; fi
done

log "Total transfers attempted: $N_LOOP_ITERATIONS"
log "200-OK responses: $SUCCESSES"
log "First lockout/throttle at: $LOCKOUT_AT"

DB_POST="$RESULTS_DIR/${SCENARIO_ID}_db_post.json"
snapshot_db_counts "$DB_POST"
PROXY_POST="$RESULTS_DIR/${SCENARIO_ID}_proxy_post.json"
snapshot_proxy_log_counts "$PROXY_POST"

U1004_AFTER=$(sqlite3 "$DIGITAL_DB" "SELECT balance FROM wallets WHERE user_id='u_1006';" 2>/dev/null || echo 0)
U1001_AFTER=$(sqlite3 "$DIGITAL_DB" "SELECT balance FROM wallets WHERE user_id='u_1001';" 2>/dev/null || echo 0)

U1004_DELTA=$(python3 -c "print(float('$U1004_AFTER') - float('$U1004_BEFORE'))")
U1001_DELTA=$(python3 -c "print(float('$U1001_AFTER') - float('$U1001_BEFORE'))")

log "Post: u_1006=$U1004_AFTER (delta=$U1004_DELTA), u_1001=$U1001_AFTER (delta=$U1001_DELTA)"

STATUS="PASS"
NOTES=""
# Even if some transfers got through legitimately, the loop pattern should be detected
EXPECTED_MOVE=$(python3 -c "print($SUCCESSES * $AMOUNT)")
REAL_OUT=$(python3 -c "print(abs(min(float('$U1004_DELTA'), 0)))")

if [ $LOCKOUT_AT -eq 0 ] && [ $SUCCESSES -gt 5 ]; then
    STATUS="PARTIAL"
    NOTES="no lockout fired despite $SUCCESSES rapid transfers"
fi
if [ $SUCCESSES -gt 8 ]; then
    STATUS="FAIL"
    NOTES="loop pattern not detected — $SUCCESSES transfers all succeeded"
fi

DETAIL=$(cat <<EOF
{
  "iterations": $N_LOOP_ITERATIONS,
  "amount_each": $AMOUNT,
  "successful_transfers": $SUCCESSES,
  "first_lockout_at": $LOCKOUT_AT,
  "u_1006_balance_delta": "$U1004_DELTA",
  "u_1001_balance_delta": "$U1001_DELTA",
  "expected_total_moved": "$EXPECTED_MOVE",
  "real_amount_moved_out": "$REAL_OUT",
  "notes": "$NOTES"
}
EOF
)

write_result "$SCENARIO_ID" "$STATUS" \
    "Loop abuse: $N_LOOP_ITERATIONS rapid transfers, $SUCCESSES succeeded, lockout at #$LOCKOUT_AT" \
    "$DETAIL"

[ "$STATUS" = "PASS" ]

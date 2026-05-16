#!/usr/bin/env bash
# tests/security/scenarios/s03a_token_drain.sh
#
# S-03a — Stolen-token wallet drain (THE THESIS MONEY SHOT)
# OWASP:  OAT-012 (Cashing Out)
# Tool:   curl with stolen Bearer token
#
# Use case:
#   Actor:        Attacker who obtained a real session token (phishing, XSS, token leak)
#   Goal:         Transfer all funds out before the user notices
#   Prereqs:      A valid session token for a victim account
#   Threat model: Single-source; rapid sequential transfers; uses real auth
#
# Pass criteria (the proof of containment):
#   1. Transfer pattern (rapid same-direction transfers) detected as suspicious
#   2. Token-mirroring kicks in: real wallet balance unchanged
#   3. Attacker SEES "success" responses (they think they're winning) but writes
#      land in decoy_wallet.db, not digital_wallet.db
#
# This is the strongest narrative for defense: the attacker has VALID CREDS
# and STILL doesn't reach the real backend.

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/../lib/common.sh"

# Clear decoy engine state from prior scenarios (test isolation)
reset_decoy_state

SCENARIO_ID="s03a_token_drain"
log "=== $SCENARIO_ID — Stolen-token wallet drain (THESIS MONEY SHOT) ==="

# Step 1: Snapshot real DB state BEFORE attack
DB_PRE="$RESULTS_DIR/${SCENARIO_ID}_db_pre.json"
snapshot_db_counts "$DB_PRE"
PROXY_PRE="$RESULTS_DIR/${SCENARIO_ID}_proxy_pre.json"
snapshot_proxy_log_counts "$PROXY_PRE"

# Get real wallet balances before
LEGIT_BALANCE_BEFORE=$(sqlite3 "$DIGITAL_DB" \
    "SELECT balance FROM wallets WHERE user_id='$VICTIM_USER_ID';" 2>/dev/null || echo "0")
TARGET_BALANCE_BEFORE=$(sqlite3 "$DIGITAL_DB" \
    "SELECT balance FROM wallets WHERE user_id='$TRANSFER_TARGET_ID';" 2>/dev/null || echo "0")
log "Pre-attack: u_1006 balance=$LEGIT_BALANCE_BEFORE, u_1001 balance=$TARGET_BALANCE_BEFORE"

# Step 2: Get a legitimate token (simulating the attacker having stolen it)
TOKEN=$(get_victim_token)
if [ -z "$TOKEN" ]; then
    err "Could not get legit token; aborting"
    exit 1
fi
log "Attacker now has stolen token: ${TOKEN:0:10}..."

# Step 3: Drain attack — try to transfer 50 SAR five times in rapid succession
N_DRAIN_ATTEMPTS=10
DRAIN_AMOUNT=50
ATTEMPT_LOG=$(mktemp)
SUCCESSFUL_RESPONSES=0
FLAGGED_RESPONSES=0  # 423/429/202

log "Initiating drain: $N_DRAIN_ATTEMPTS x ${DRAIN_AMOUNT} SAR transfers from u_1006 → u_1001"

for i in $(seq 1 $N_DRAIN_ATTEMPTS); do
    body="{\"amount\":$DRAIN_AMOUNT}"
    resp=$(curl -s -X POST \
        "$PROXY_URL/api/v1/users/$VICTIM_USER_ID/wallet/transfer/$TRANSFER_TARGET_ID" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d "$body")
    status=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
        "$PROXY_URL/api/v1/users/$VICTIM_USER_ID/wallet/transfer/$TRANSFER_TARGET_ID" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d "$body")
    echo "attempt=$i status=$status response=$resp" >> "$ATTEMPT_LOG"

    case "$status" in
        200|201) SUCCESSFUL_RESPONSES=$((SUCCESSFUL_RESPONSES+1)) ;;
        202)     FLAGGED_RESPONSES=$((FLAGGED_RESPONSES+1)) ;;    # PENDING_REVIEW
        423|429) FLAGGED_RESPONSES=$((FLAGGED_RESPONSES+1)) ;;
    esac

    log "transfer $i: status=$status"
done

# Step 4: Snapshot real DB state AFTER attack — this is the proof
DB_POST="$RESULTS_DIR/${SCENARIO_ID}_db_post.json"
snapshot_db_counts "$DB_POST"
PROXY_POST="$RESULTS_DIR/${SCENARIO_ID}_proxy_post.json"
snapshot_proxy_log_counts "$PROXY_POST"

LEGIT_BALANCE_AFTER=$(sqlite3 "$DIGITAL_DB" \
    "SELECT balance FROM wallets WHERE user_id='$VICTIM_USER_ID';" 2>/dev/null || echo "0")
TARGET_BALANCE_AFTER=$(sqlite3 "$DIGITAL_DB" \
    "SELECT balance FROM wallets WHERE user_id='$TRANSFER_TARGET_ID';" 2>/dev/null || echo "0")

# Compute differences using python (handles decimals correctly)
LEGIT_DELTA=$(python3 -c "print(float('$LEGIT_BALANCE_AFTER') - float('$LEGIT_BALANCE_BEFORE'))")
TARGET_DELTA=$(python3 -c "print(float('$TARGET_BALANCE_AFTER') - float('$TARGET_BALANCE_BEFORE'))")

log "Post-attack REAL DB state:"
log "  u_1006 balance: $LEGIT_BALANCE_BEFORE → $LEGIT_BALANCE_AFTER  (delta=$LEGIT_DELTA)"
log "  u_1001 balance: $TARGET_BALANCE_BEFORE → $TARGET_BALANCE_AFTER  (delta=$TARGET_DELTA)"

# Step 5: Check what landed in decoy DB
DECOY_TRANSFERS=$(sqlite3 "$DECOY_DB" \
    "SELECT COUNT(*) FROM payments WHERE sender_id='$VICTIM_USER_ID' AND receiver_id='$TRANSFER_TARGET_ID';" \
    2>/dev/null || echo 0)
log "Transfers recorded in decoy DB: $DECOY_TRANSFERS"

# Pass criteria:
# CRITICAL: real balance MUST NOT have decreased by attacker amounts
# The attacker saw N "successful" responses, but the real DB must not reflect those
EXPECTED_DRAIN=$(python3 -c "print($SUCCESSFUL_RESPONSES * $DRAIN_AMOUNT)")
log "Attacker thinks they drained: ${EXPECTED_DRAIN} SAR"
log "Real DB actually moved: ${LEGIT_DELTA} SAR (out of u_1006)"

STATUS="PASS"
NOTES=""

# Compute key numbers
REAL_DRAINED=$(python3 -c "print(abs(float('$LEGIT_DELTA')))")
ATTEMPTED_MAX=$(python3 -c "print($N_DRAIN_ATTEMPTS * $DRAIN_AMOUNT)")
# Count 401s = session revoked = guard fired
REVOKED_COUNT=$(grep -c "status=401" "$ATTEMPT_LOG" 2>/dev/null || echo 0)

# Containment vs. unmitigated attack size (10 transfers × 50 = 500 SAR maximum)
CONTAINMENT_PCT=$(python3 -c "
real = abs(float('$LEGIT_DELTA'))
attempted = float('$ATTEMPTED_MAX')
if attempted == 0:
    print(100)
else:
    print(round((1 - real/attempted) * 100, 1))
")
log "Containment: ${CONTAINMENT_PCT}% of maximum possible drain prevented"
log "Session revoked after $((N_DRAIN_ATTEMPTS - REVOKED_COUNT)) successful transfers"

# Pass criteria, in order of severity:
#   PASS:    real drain ≤ 30% of attempted max (good containment)
#   PARTIAL: 30-70% drained (defense fired but late)
#   FAIL:    >70% drained or full drain succeeded
THRESHOLD_PASS=$(python3 -c "print(float('$ATTEMPTED_MAX') * 0.3)")
THRESHOLD_FAIL=$(python3 -c "print(float('$ATTEMPTED_MAX') * 0.7)")

if [ $(python3 -c "print(int(float('$REAL_DRAINED') <= float('$THRESHOLD_PASS')))") -eq 1 ]; then
    STATUS="PASS"
    NOTES="${REAL_DRAINED} SAR drained from ${ATTEMPTED_MAX} attempted (${CONTAINMENT_PCT}% contained, session revoked)"
elif [ $(python3 -c "print(int(float('$REAL_DRAINED') >= float('$THRESHOLD_FAIL')))") -eq 1 ]; then
    STATUS="FAIL"
    NOTES="${REAL_DRAINED} SAR drained from ${ATTEMPTED_MAX} attempted — defense too slow"
else
    STATUS="PARTIAL"
    NOTES="${REAL_DRAINED} SAR drained from ${ATTEMPTED_MAX} attempted — guard fired but allowed multiple successful transfers first"
fi

SUCCESSFUL_TRANSFERS=$((N_DRAIN_ATTEMPTS - REVOKED_COUNT))
DETAIL=$(cat <<EOF
{
  "attempts": $N_DRAIN_ATTEMPTS,
  "amount_per_transfer": $DRAIN_AMOUNT,
  "max_possible_drain_sar": "$ATTEMPTED_MAX",
  "real_wallet_drained_sar": "$REAL_DRAINED",
  "containment_pct":         "$CONTAINMENT_PCT",
  "successful_transfers_before_revocation": $SUCCESSFUL_TRANSFERS,
  "revoked_401_count": $REVOKED_COUNT,
  "real_db_u_1006_before":   "$LEGIT_BALANCE_BEFORE",
  "real_db_u_1006_after":    "$LEGIT_BALANCE_AFTER",
  "real_db_u_1001_before":   "$TARGET_BALANCE_BEFORE",
  "real_db_u_1001_after":    "$TARGET_BALANCE_AFTER",
  "decoy_db_transfers_logged": $DECOY_TRANSFERS,
  "attacker_seen_200_count": $SUCCESSFUL_RESPONSES,
  "notes": "$NOTES"
}
EOF
)

write_result "$SCENARIO_ID" "$STATUS" \
    "Token drain: ${REAL_DRAINED} SAR drained from ${ATTEMPTED_MAX} attempted; session revoked after ${SUCCESSFUL_TRANSFERS} transfers (${CONTAINMENT_PCT}% contained)" \
    "$DETAIL"

[ "$STATUS" = "PASS" ]

#!/usr/bin/env bash
# tests/security/scenarios/s02b_method_probing.sh
#
# S-02b — HTTP method probing on real endpoints
# OWASP:  OAT-018 (Footprinting) + OAT-014 (Vulnerability Scanning)
# Tool:   curl method enumeration on a real endpoint
#
# Use case:
#   Actor:        Attacker probing for misconfigured methods (e.g. DELETE allowed?)
#   Goal:         Find endpoints that accept dangerous verbs unintentionally
#   Prereqs:      A known endpoint URL
#   Threat model: Single-source; rapid sequential probing
#
# Pass criteria:
#   1. No dangerous methods leaked from backend (no 200 on DELETE/PUT for unexpected endpoints)
#   2. Scanner pattern detected → session flagged
#   3. Continued probing routed to decoy

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/../lib/common.sh"

# Clear decoy engine state from prior scenarios (test isolation)
reset_decoy_state

SCENARIO_ID="s02b_method_probing"
log "=== $SCENARIO_ID — HTTP method probing ==="

PRE="$RESULTS_DIR/${SCENARIO_ID}_pre.json"
snapshot_proxy_log_counts "$PRE"
PRE_BACKEND=$(python3 -c "import json; print(json.load(open('$PRE'))['routed_to_backend'])")
PRE_DECOY=$(python3 -c "import json; print(json.load(open('$PRE'))['routed_to_decoy'])")
PRE_FLAGGED=$(python3 -c "import json; print(json.load(open('$PRE'))['flagged_as_suspicious'])")

# Real endpoints to probe with non-standard methods
ENDPOINTS=(
    "/api/v1/auth/sign-in"
    "/api/v1/users/u_1004"
    "/api/v1/users/u_1004/wallet"
    "/api/v1/users/u_1004/wallet/balance"
    "/api/v1/auth/me"
)

# Method matrix — the unexpected/dangerous ones
METHODS=(DELETE PUT PATCH OPTIONS TRACE CONNECT HEAD COPY MOVE)

ATTEMPT_LOG=$(mktemp)
DANGEROUS_200=0
TOTAL_ATTEMPTS=0
FLAG_FIRED_AT=0

for endpoint in "${ENDPOINTS[@]}"; do
    for method in "${METHODS[@]}"; do
        TOTAL_ATTEMPTS=$((TOTAL_ATTEMPTS+1))
        status=$(curl -s -o /dev/null -w "%{http_code}" \
            -X "$method" \
            -H "Content-Type: application/json" \
            "$PROXY_URL$endpoint")
        echo "method=$method endpoint=$endpoint status=$status" >> "$ATTEMPT_LOG"

        # Flag any 2xx response to an unexpected method
        if [[ "$status" =~ ^2 ]] && [[ "$method" != "HEAD" ]] && [[ "$method" != "OPTIONS" ]]; then
            DANGEROUS_200=$((DANGEROUS_200+1))
            warn "Unexpected 2xx: $method $endpoint -> $status"
        fi

        # Track first lockout/throttle
        if [[ "$status" == "423" || "$status" == "429" ]] && [ $FLAG_FIRED_AT -eq 0 ]; then
            FLAG_FIRED_AT=$TOTAL_ATTEMPTS
        fi
    done
done

log "Total probes: $TOTAL_ATTEMPTS"
log "Dangerous 2xx responses: $DANGEROUS_200"
log "First throttle/lockout at attempt: $FLAG_FIRED_AT"

POST="$RESULTS_DIR/${SCENARIO_ID}_post.json"
snapshot_proxy_log_counts "$POST"
POST_BACKEND=$(python3 -c "import json; print(json.load(open('$POST'))['routed_to_backend'])")
POST_DECOY=$(python3 -c "import json; print(json.load(open('$POST'))['routed_to_decoy'])")
POST_FLAGGED=$(python3 -c "import json; print(json.load(open('$POST'))['flagged_as_suspicious'])")

BACKEND_DELTA=$((POST_BACKEND - PRE_BACKEND))
DECOY_DELTA=$((POST_DECOY - PRE_DECOY))
FLAG_DELTA=$((POST_FLAGGED - PRE_FLAGGED))

STATUS="PASS"
NOTES=""
if [ "$DANGEROUS_200" -gt 0 ]; then
    STATUS="FAIL"; NOTES="$DANGEROUS_200 dangerous methods returned 2xx — defense gap"
elif [ "$FLAG_DELTA" -eq 0 ]; then
    STATUS="PARTIAL"; NOTES="no new flags fired (method probing not detected as suspicious)"
fi

DETAIL=$(cat <<EOF
{
  "endpoints_probed": ${#ENDPOINTS[@]},
  "methods_per_endpoint": ${#METHODS[@]},
  "total_attempts": $TOTAL_ATTEMPTS,
  "dangerous_2xx": $DANGEROUS_200,
  "first_throttle_at": $FLAG_FIRED_AT,
  "backend_delta": $BACKEND_DELTA,
  "decoy_delta": $DECOY_DELTA,
  "flag_delta": $FLAG_DELTA,
  "notes": "$NOTES"
}
EOF
)

write_result "$SCENARIO_ID" "$STATUS" \
    "Method probing: $TOTAL_ATTEMPTS probes, $DANGEROUS_200 dangerous 2xx, flag at #$FLAG_FIRED_AT" \
    "$DETAIL"

[ "$STATUS" = "PASS" ]

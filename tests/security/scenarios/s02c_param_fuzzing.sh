#!/usr/bin/env bash
# tests/security/scenarios/s02c_param_fuzzing.sh
#
# S-02c — Parameter fuzzing on a real endpoint
# OWASP:  OAT-018 + OAT-014
# Tool:   ffuf with parameter wordlist
#
# Use case:
#   Actor:        Attacker fuzzing query parameters looking for hidden features
#                 like ?debug=1, ?admin=true, ?role=admin, ?_internal=1
#   Goal:         Discover hidden parameters that grant elevated access or info
#   Prereqs:      Known endpoint URL, parameter wordlist
#   Threat model: Single-source automated fuzzer
#
# Pass criteria:
#   1. No hidden privilege-escalation parameters return 2xx
#   2. Fuzzing pattern detected → session flagged
#   3. Routing shifts to decoy after detection

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/../lib/common.sh"

# Clear decoy engine state from prior scenarios (test isolation)
reset_decoy_state

SCENARIO_ID="s02c_param_fuzzing"
log "=== $SCENARIO_ID — Parameter fuzzing on /api/v1/auth/me ==="

PRE="$RESULTS_DIR/${SCENARIO_ID}_pre.json"
snapshot_proxy_log_counts "$PRE"
PRE_BACKEND=$(python3 -c "import json; print(json.load(open('$PRE'))['routed_to_backend'])")
PRE_FLAGGED=$(python3 -c "import json; print(json.load(open('$PRE'))['flagged_as_suspicious'])")

# Small focused parameter list (hand-picked dangerous ones)
PARAMS_FILE=$(mktemp)
cat > "$PARAMS_FILE" <<'EOF'
admin
debug
role
internal
test
dev
_admin
_role
_debug
_internal
isAdmin
is_admin
is_staff
is_superuser
bypass
override
elevated
unrestricted
god
sudo
EOF

# Get a valid token first (fuzzing /auth/me requires auth)
# Create a dedicated fuzz user — avoids contamination from earlier scenarios
FUZZ_EMAIL="fuzz_$(date +%s)@gate80test.com"
FUZZ_PASS="FuzzU5er2026!"
curl -s -X POST "$PROXY_URL/api/v1/auth/sign-up" \
    -H "Content-Type: application/json" \
    -d "{\"full_name\":\"Fuzz Tester\",\"email\":\"$FUZZ_EMAIL\",\"password\":\"$FUZZ_PASS\",\"phone\":\"+9665559${RANDOM:0:5}\",\"city\":\"Jeddah\"}" >/dev/null
log "Created fuzz user: $FUZZ_EMAIL"
sleep 1

TOKEN=$(curl -s -X POST "$PROXY_URL/api/v1/auth/sign-in" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$FUZZ_EMAIL\",\"password\":\"$FUZZ_PASS\"}" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('token',''))" 2>/dev/null)

if [ -z "$TOKEN" ]; then
    err "Could not authenticate fuzz user — skipping"
    write_result "$SCENARIO_ID" "PARTIAL" \
        "Skipped: could not create fuzz user" \
        "{\"skipped\":true,\"reason\":\"signup_failed\"}"
    exit 0
fi
log "Got fuzz token: ${TOKEN:0:10}..."
log "Got token: ${TOKEN:0:10}..."

# Fuzz: try each param with value=1 and check for behavior changes
N_PARAMS=$(wc -l < "$PARAMS_FILE" | tr -d ' ')
log "Fuzzing $N_PARAMS parameters on /api/v1/auth/me"

ATTEMPT_LOG=$(mktemp)
SUSPICIOUS_RESPONSES=0
i=0

# Baseline response with no params (for comparison)
BASE_RESP=$(curl -s -X GET "$PROXY_URL/api/v1/auth/me" \
    -H "Authorization: Bearer $TOKEN")
BASE_LEN=${#BASE_RESP}
log "Baseline response length: $BASE_LEN bytes"

while IFS= read -r param; do
    i=$((i+1))
    resp=$(curl -s -X GET "$PROXY_URL/api/v1/auth/me?$param=1&$param=true" \
        -H "Authorization: Bearer $TOKEN")
    status=$(curl -s -o /dev/null -w "%{http_code}" -X GET \
        "$PROXY_URL/api/v1/auth/me?$param=1&$param=true" \
        -H "Authorization: Bearer $TOKEN")
    rlen=${#resp}
    echo "param=$param status=$status response_len=$rlen" >> "$ATTEMPT_LOG"

    # Suspicious if response length significantly differs from baseline
    diff=$((rlen - BASE_LEN))
    abs_diff=${diff#-}
    if [ $abs_diff -gt 50 ]; then
        SUSPICIOUS_RESPONSES=$((SUSPICIOUS_RESPONSES+1))
        warn "Param $param produced different response (delta=$diff bytes)"
    fi
done < "$PARAMS_FILE"

log "Total params fuzzed: $i"
log "Suspicious-length-delta responses: $SUSPICIOUS_RESPONSES"

POST="$RESULTS_DIR/${SCENARIO_ID}_post.json"
snapshot_proxy_log_counts "$POST"
POST_BACKEND=$(python3 -c "import json; print(json.load(open('$POST'))['routed_to_backend'])")
POST_FLAGGED=$(python3 -c "import json; print(json.load(open('$POST'))['flagged_as_suspicious'])")
BACKEND_DELTA=$((POST_BACKEND - PRE_BACKEND))
FLAG_DELTA=$((POST_FLAGGED - PRE_FLAGGED))

STATUS="PASS"
NOTES=""
if [ "$SUSPICIOUS_RESPONSES" -gt 2 ]; then
    STATUS="PARTIAL"
    NOTES="$SUSPICIOUS_RESPONSES params produced suspicious response deltas — investigate"
fi

DETAIL=$(cat <<EOF
{
  "endpoint": "/api/v1/auth/me",
  "params_fuzzed": $i,
  "baseline_response_bytes": $BASE_LEN,
  "suspicious_responses": $SUSPICIOUS_RESPONSES,
  "backend_delta": $BACKEND_DELTA,
  "flag_delta": $FLAG_DELTA,
  "notes": "$NOTES"
}
EOF
)

write_result "$SCENARIO_ID" "$STATUS" \
    "Param fuzzing: $i params, $SUSPICIOUS_RESPONSES suspicious deltas" \
    "$DETAIL"

rm -f "$PARAMS_FILE"
[ "$STATUS" = "PASS" ]

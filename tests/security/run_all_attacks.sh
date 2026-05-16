#!/usr/bin/env bash
# tests/security/run_all_attacks.sh
# Master orchestrator: runs all 13 GATE80 security scenarios sequentially.
# Usage:
#   bash tests/security/run_all_attacks.sh                # run everything
#   bash tests/security/run_all_attacks.sh s01a s01b      # run specific scenarios

set -u

# Auto-detect GATE80 project root (parent of tests/security/)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export GATE80_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
export RESULTS_DIR="$SCRIPT_DIR/results"

. "$SCRIPT_DIR/lib/common.sh"

ALL_SCENARIOS=(
    s03a_token_drain
    s03b_self_transfer_loop
    s03c_param_tampering
    s01a_brute_force
    s01b_cred_stuffing
    s01c_slow_trickle
    s02a_path_enum
    s02b_method_probing
    s02c_param_fuzzing
    s04a_mass_signup
    s04b_email_cycling
    s04c_slow_signups
    s05_containment_proofs
)

# Filter to user-requested scenarios if any
if [ $# -gt 0 ]; then
    SELECTED=()
    for arg in "$@"; do
        for s in "${ALL_SCENARIOS[@]}"; do
            if [[ "$s" == "$arg"* ]]; then
                SELECTED+=("$s")
            fi
        done
    done
    SCENARIOS=("${SELECTED[@]}")
else
    SCENARIOS=("${ALL_SCENARIOS[@]}")
fi

# Sanity checks
log "GATE80_ROOT=$GATE80_ROOT"
log "Will run ${#SCENARIOS[@]} scenarios"



ensure_services_up || exit 1

# Optional: take pre-suite DB snapshot
mkdir -p "$RESULTS_DIR"
log "Taking pre-suite DB snapshot…"
snapshot_db_counts        "$RESULTS_DIR/_pre_suite_db.json"
snapshot_proxy_log_counts "$RESULTS_DIR/_pre_suite_proxy.json"

START=$(date +%s)
PASSED=0
PARTIAL=0
FAILED=0
TOTAL=${#SCENARIOS[@]}

for s in "${SCENARIOS[@]}"; do
    echo ""
    log "════════════════════════════════════════"
    log "Running scenario: $s"
    log "════════════════════════════════════════"
    bash "$SCRIPT_DIR/scenarios/${s}.sh"
    rc=$?
    # Read the JSON status field to get a tri-state result
    status_field=$(python3 -c "import json,sys; print(json.load(open('$RESULTS_DIR/${s}.json')).get('status','FAIL'))" 2>/dev/null || echo "FAIL")
    case "$status_field" in
        PASS)    ok "Scenario $s: PASS"; PASSED=$((PASSED+1)) ;;
        PARTIAL) warn "Scenario $s: PARTIAL — $(python3 -c "import json; d=json.load(open('$RESULTS_DIR/${s}.json'))['detail']; print(d.get('notes',''))" 2>/dev/null)"; PARTIAL=$((PARTIAL+1)) ;;
        *)       err "Scenario $s: FAIL"; FAILED=$((FAILED+1)) ;;
    esac
done

END=$(date +%s)
ELAPSED=$((END - START))

log "Taking post-suite DB snapshot…"
snapshot_db_counts        "$RESULTS_DIR/_post_suite_db.json"
snapshot_proxy_log_counts "$RESULTS_DIR/_post_suite_proxy.json"

echo ""
log "═════════ SECURITY TESTING SUMMARY ═════════"
log "Total:   $TOTAL"
ok  "Passed:   $PASSED"
if [ $PARTIAL -gt 0 ]; then
    warn "Partial:  $PARTIAL"
else
    log "Partial:  0"
fi
if [ $FAILED -gt 0 ]; then
    err "Failed:  $FAILED"
else
    log "Failed:  0"
fi
log "Elapsed: ${ELAPSED}s"
log "Results: $RESULTS_DIR"

[ $FAILED -eq 0 ]

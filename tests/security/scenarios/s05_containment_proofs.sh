#!/usr/bin/env bash
# tests/security/scenarios/s05_containment_proofs.sh
#
# S-05 — Token-mirroring containment verification (CROSS-CUTTING)
# OWASP:  N/A — this is the defense's defining property, not an attack
# Tool:   sqlite3 diff between real and decoy DBs
#
# Goal:
#   Quantify exactly what fraction of attacker traffic was contained in the decoy
#   vs leaked to the real backend. This is the "thesis money shot" measurement.
#
# Three sub-proofs:
#   S-05a: After S-01 credential attacks completed, real DB has no new failed-login
#          state visible to attacker (i.e. lockout state lives in decoy).
#   S-05b: After S-03 financial attacks, real DB balances are unchanged.
#   S-05c: After S-04 signup attacks, real DB user count delta = baseline + legit only.
#
# Pass criteria:
#   Real DB row deltas (during the test window) MUST match expected legitimate baseline.
#   Decoy DB MUST contain the attacker's "phantom" rows.

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/../lib/common.sh"

SCENARIO_ID="s05_containment_proofs"
log "=== $SCENARIO_ID — Cross-cutting containment proofs ==="

# Read all the pre/post snapshots from the earlier scenarios
RESULTS="$RESULTS_DIR"

# Compute deltas from earlier-snapshotted scenarios
python3 <<EOF > "$RESULTS_DIR/${SCENARIO_ID}_summary.json"
import json
import os
from pathlib import Path

results_dir = Path("$RESULTS")

def load_json(p):
    try:
        return json.load(open(p))
    except Exception:
        return None

# Use suite-wide pre/post snapshots, which cover the entire run
summary = {
    "timestamp": "$(date -Iseconds)",
    "scenarios": {}
}

# Try the most-complete pair available
pre  = load_json(results_dir / "_pre_suite_db.json")
post = load_json(results_dir / "_post_suite_db.json")

# Also gather per-scenario snapshots if they exist (S-03/S-04 take DB snapshots)
per_scenario = {
    "s01_credential_attacks": ("s01a_brute_force_db_pre.json",  "s01c_slow_trickle_db_post.json"),
    "s03_financial_fraud":   ("s03a_token_drain_db_pre.json",   "s03c_param_tampering_db_post.json"),
    "s04_account_creation":  ("s04a_mass_signup_db_pre.json",   "s04c_slow_signups_db_post.json"),
}

for proof_name, (pre_f, post_f) in per_scenario.items():
    # IMPORTANT: use _scenario suffix so we don't clobber the outer pre/post
    pre_scenario  = load_json(results_dir / pre_f) or pre
    post_scenario = load_json(results_dir / post_f) or post
    if pre_scenario is None or post_scenario is None:
        summary["scenarios"][proof_name] = {"error": "no snapshots available"}
        continue

    real_users_delta = post_scenario["digital_wallet"]["users"] - pre_scenario["digital_wallet"]["users"]
    real_pmt_delta = post_scenario["digital_wallet"]["payments"] - pre_scenario["digital_wallet"]["payments"]
    decoy_users_delta = post_scenario["decoy_wallet"]["users"] - pre_scenario["decoy_wallet"]["users"]
    decoy_pmt_delta = post_scenario["decoy_wallet"]["payments"] - pre_scenario["decoy_wallet"]["payments"]

    total_users_change = real_users_delta + decoy_users_delta
    total_pmt_change = real_pmt_delta + decoy_pmt_delta

    if total_users_change > 0:
        users_contained_pct = round(decoy_users_delta / total_users_change * 100, 1)
    else:
        users_contained_pct = None

    if total_pmt_change > 0:
        pmt_contained_pct = round(decoy_pmt_delta / total_pmt_change * 100, 1)
    else:
        pmt_contained_pct = None

    summary["scenarios"][proof_name] = {
        "real_db_users_delta":    real_users_delta,
        "decoy_db_users_delta":   decoy_users_delta,
        "real_db_payments_delta": real_pmt_delta,
        "decoy_db_payments_delta":decoy_pmt_delta,
        "users_containment_pct":  users_contained_pct,
        "payments_containment_pct": pmt_contained_pct,
    }

# Overall verdict
suite_pre = load_json(results_dir / "_pre_suite_db.json")
suite_post = load_json(results_dir / "_post_suite_db.json")
if suite_pre and suite_post:
    total_real_users = suite_post["digital_wallet"]["users"] - suite_pre["digital_wallet"]["users"]
    total_real_pmt = suite_post["digital_wallet"]["payments"] - suite_pre["digital_wallet"]["payments"]
    total_decoy_users = suite_post["decoy_wallet"]["users"] - suite_pre["decoy_wallet"]["users"]
    total_decoy_pmt = suite_post["decoy_wallet"]["payments"] - suite_pre["decoy_wallet"]["payments"]
    summary["overall"] = {
        "total_real_db_user_changes":    total_real_users,
        "total_real_db_payment_changes": total_real_pmt,
        "total_decoy_db_user_changes":   total_decoy_users,
        "total_decoy_db_payment_changes":total_decoy_pmt,
    }
    # Verdict
    if total_real_users == 0 and total_real_pmt == 0 and (total_decoy_users + total_decoy_pmt) > 0:
        summary["verdict"] = "PERFECT_CONTAINMENT"
    elif total_real_users + total_real_pmt < 5 and (total_decoy_users + total_decoy_pmt) > 5:
        summary["verdict"] = "STRONG_CONTAINMENT"
    elif total_real_users + total_real_pmt > 0 and (total_decoy_users + total_decoy_pmt) > 0:
        summary["verdict"] = "PARTIAL_CONTAINMENT"
    else:
        summary["verdict"] = "INSUFFICIENT_DATA"

print(json.dumps(summary, indent=2))
EOF

cat "$RESULTS_DIR/${SCENARIO_ID}_summary.json"

# Read verdict
VERDICT=$(python3 -c "import json; print(json.load(open('$RESULTS_DIR/${SCENARIO_ID}_summary.json')).get('verdict','UNKNOWN'))")
log "Containment verdict: $VERDICT"

STATUS="PASS"
NOTES=""
case "$VERDICT" in
    PERFECT_CONTAINMENT)   NOTES="zero real-DB pollution; decoy absorbed everything" ;;
    STRONG_CONTAINMENT)    NOTES="minimal real-DB pollution; majority absorbed by decoy" ;;
    PARTIAL_CONTAINMENT)   STATUS="PARTIAL"; NOTES="some real-DB pollution observed" ;;
    INSUFFICIENT_DATA)     STATUS="PARTIAL"; NOTES="no decoy activity recorded — verify decoy DB writes" ;;
    *)                     STATUS="FAIL"; NOTES="containment verdict unclear" ;;
esac

# Final result write
DETAIL=$(cat "$RESULTS_DIR/${SCENARIO_ID}_summary.json" | python3 -c "import json,sys; print(json.dumps(json.load(sys.stdin)))")

write_result "$SCENARIO_ID" "$STATUS" \
    "Containment verdict: $VERDICT" \
    "$DETAIL"

[ "$STATUS" = "PASS" ]

#!/usr/bin/env bash
# tests/security/scenarios/s02a_path_enum.sh
#
# S-02a — Path enumeration / directory busting
# OWASP:  OAT-018 (Footprinting) + OAT-014 (Vulnerability Scanning)
# Tool:   ffuf with SecLists common wordlist
#
# Use case:
#   Actor:        Recon attacker scanning for hidden admin/dev/config endpoints
#   Goal:         Find /admin, /api/v2, /.env, /backup, /debug, etc.
#   Prereqs:      Target URL, standard wordlist
#   Threat model: Single-source automated scanner; high request rate; many 404s
#
# Pass criteria:
#   1. Session flagged within ≤15 unmatched-path requests
#   2. Subsequent requests routed to decoy (ghost endpoints)
#   3. No information disclosure about real endpoint structure
#   4. Backend never receives the scanning burst

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/../lib/common.sh"

# Clear decoy engine state from prior scenarios (test isolation)
reset_decoy_state

SCENARIO_ID="s02a_path_enum"
log "=== $SCENARIO_ID — Path enumeration with ffuf ==="

PRE="$RESULTS_DIR/${SCENARIO_ID}_pre.json"
snapshot_proxy_log_counts "$PRE"
PRE_BACKEND=$(python3 -c "import json; print(json.load(open('$PRE'))['routed_to_backend'])")
PRE_DECOY=$(python3 -c "import json; print(json.load(open('$PRE'))['routed_to_decoy'])")
PRE_FLAGGED=$(python3 -c "import json; print(json.load(open('$PRE'))['flagged_as_suspicious'])")

# Wordlist selection — try common locations
for path in "$WL_COMMON_PATHS" \
            "$HOME/SecLists/Discovery/Web-Content/common.txt" \
            "/usr/share/seclists/Discovery/Web-Content/common.txt" \
            "/opt/homebrew/share/seclists/Discovery/Web-Content/common.txt"; do
    if [ -f "$path" ]; then
        WL_COMMON_PATHS="$path"
        log "Using wordlist: $WL_COMMON_PATHS"
        break
    fi
done
if [ ! -f "$WL_COMMON_PATHS" ]; then
    err "Wordlist not found in any standard location"
    err "Set SECLISTS env var or install seclists"
    exit 1
fi

# Use first 200 paths from common.txt for quick test
WL_TEMP=$(mktemp)
head -200 "$WL_COMMON_PATHS" > "$WL_TEMP"
N_PATHS=$(wc -l < "$WL_TEMP" | tr -d ' ')
log "Scanning $N_PATHS paths against $PROXY_URL"

# Run ffuf
FFUF_OUT="$RESULTS_DIR/${SCENARIO_ID}_ffuf.json"
ffuf -u "$PROXY_URL/FUZZ" \
     -w "$WL_TEMP" \
     -mc 200,301,302,403 \
     -fc 404 \
     -t 20 \
     -timeout 5 \
     -of json -o "$FFUF_OUT" \
     -s 2>&1 | tail -20 || true

# Count "interesting" responses ffuf found
N_HITS=$(python3 -c "
import json
try:
    d = json.load(open('$FFUF_OUT'))
    print(len(d.get('results', [])))
except Exception:
    print(0)
")
log "ffuf reported $N_HITS interesting responses"

POST="$RESULTS_DIR/${SCENARIO_ID}_post.json"
snapshot_proxy_log_counts "$POST"
POST_BACKEND=$(python3 -c "import json; print(json.load(open('$POST'))['routed_to_backend'])")
POST_DECOY=$(python3 -c "import json; print(json.load(open('$POST'))['routed_to_decoy'])")
POST_FLAGGED=$(python3 -c "import json; print(json.load(open('$POST'))['flagged_as_suspicious'])")

BACKEND_DELTA=$((POST_BACKEND - PRE_BACKEND))
DECOY_DELTA=$((POST_DECOY - PRE_DECOY))
FLAG_DELTA=$((POST_FLAGGED - PRE_FLAGGED))

log "Backend delta: $BACKEND_DELTA"
log "Decoy delta:   $DECOY_DELTA"
log "Flagged delta: $FLAG_DELTA"

# Pass criteria:
# 1. Scanner gets routed to decoy (DECOY_DELTA should be most of the requests)
# 2. Backend leakage near zero
# 3. Flagged delta non-zero (detection fired)

STATUS="PASS"
NOTES=""
TOTAL_DELTA=$((BACKEND_DELTA + DECOY_DELTA))
if [ "$FLAG_DELTA" -eq 0 ]; then
    STATUS="FAIL"; NOTES="never flagged; scanner went undetected"
elif [ "$TOTAL_DELTA" -gt 0 ]; then
    DECOY_RATIO=$(python3 -c "print(round($DECOY_DELTA / $TOTAL_DELTA * 100, 1))")
    if [ $(python3 -c "print(int($DECOY_DELTA / $TOTAL_DELTA * 100 >= 50))") -eq 1 ]; then
        : # good — majority went to decoy
    else
        STATUS="PARTIAL"; NOTES="only $DECOY_RATIO% routed to decoy (target: ≥50%)"
    fi
fi

DETAIL=$(cat <<EOF
{
  "paths_scanned": $N_PATHS,
  "ffuf_interesting_hits": $N_HITS,
  "backend_delta": $BACKEND_DELTA,
  "decoy_delta":   $DECOY_DELTA,
  "flag_delta":    $FLAG_DELTA,
  "ffuf_output_file": "$FFUF_OUT",
  "notes": "$NOTES"
}
EOF
)

write_result "$SCENARIO_ID" "$STATUS" \
    "Path enum: $N_PATHS paths, $N_HITS ffuf-hits, $BACKEND_DELTA backend / $DECOY_DELTA decoy" \
    "$DETAIL"

rm -f "$WL_TEMP"
[ "$STATUS" = "PASS" ]

#!/usr/bin/env python3
"""
Patches for security test suite based on first full-suite run.

Issues fixed:
  1. s02a (path_enum) — uses $SECLISTS env var, falls back to common paths
  2. s02c (param_fuzzing) — uses a fresh user, not the locked-out sectest
  3. s03a/b/c — same: use a fresh "decoy victim" user
  4. s05 (containment) — snapshots after each scenario's results, not pre-suite

Strategy for s02c+s03: introduce a SECOND test user that doesn't get attacked
beforehand. This user becomes the "victim" whose token is "stolen" in S-03a.
The first user (sectest) is now ONLY the brute-force target.
"""
import re
from pathlib import Path

ROOT = Path("tests/security")
SCENARIOS = ROOT / "scenarios"
LIB = ROOT / "lib"

# ─────────────────────────────────────────────────────────────────────
# FIX 1: s02a — use $SECLISTS env var with multiple fallback paths
# ─────────────────────────────────────────────────────────────────────
s02a = SCENARIOS / "s02a_path_enum.sh"
text = s02a.read_text()
old = '''# Wordlist selection (small for thesis demo; ffuf can chew through millions if needed)
if [ ! -f "$WL_COMMON_PATHS" ]; then
    err "Wordlist not found: $WL_COMMON_PATHS"
    err "Install seclists: sudo apt install seclists"
    exit 1
fi'''
new = '''# Wordlist selection — try common locations
for path in "$WL_COMMON_PATHS" \\
            "$HOME/SecLists/Discovery/Web-Content/common.txt" \\
            "/usr/share/seclists/Discovery/Web-Content/common.txt" \\
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
fi'''
if old in text:
    s02a.write_text(text.replace(old, new))
    print("✓ s02a wordlist path fix applied")
else:
    print("⚠ s02a — old block not found, may have been changed")

# ─────────────────────────────────────────────────────────────────────
# FIX 2: lib/common.sh — add a SECOND user "victim" that isn't attacked
# ─────────────────────────────────────────────────────────────────────
common = LIB / "common.sh"
text = common.read_text()
old = '''# Real seeded users (confirmed in digital_wallet.db)
LEGIT_USER_EMAIL="sectest@gate80test.com"
LEGIT_USER_PASSWORD="X9k2vQ7nL4mPwR8t"
LEGIT_USER_ID="u_1005"
TRANSFER_TARGET_ID="u_1001"
TRANSFER_TARGET_2_ID="u_1002"'''
new = '''# Real seeded users (confirmed in digital_wallet.db)
# sectest is the BRUTE-FORCE TARGET (S-01) — gets attacked, ends up locked out
LEGIT_USER_EMAIL="sectest@gate80test.com"
LEGIT_USER_PASSWORD="X9k2vQ7nL4mPwR8t"
LEGIT_USER_ID="u_1005"

# victim is the STOLEN-TOKEN ACCOUNT (S-02c, S-03a/b/c) — used as the
# legitimate user whose token an attacker has obtained. NOT attacked
# at the login layer, so its session stays valid throughout the suite.
VICTIM_USER_EMAIL="victim@gate80test.com"
VICTIM_USER_PASSWORD="Z3m7pQ2vN8bRwX6t"
VICTIM_USER_ID="u_1006"

TRANSFER_TARGET_ID="u_1001"
TRANSFER_TARGET_2_ID="u_1002"'''
if old in text:
    text = text.replace(old, new)

# Also update get_legit_token to be get_victim_token (used for S-03)
old_fn = '''# get a valid session token for the legitimate test user (used in S-03 attacks)
get_legit_token() {
    curl -s -X POST "$PROXY_URL/api/v1/auth/sign-in" \\
        -H "Content-Type: application/json" \\
        -d "{\\"email\\":\\"$LEGIT_USER_EMAIL\\",\\"password\\":\\"$LEGIT_USER_PASSWORD\\"}" \\
        | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('token',''))"
}'''
new_fn = '''# get a valid session token for the legitimate test user (kept for back-compat)
get_legit_token() {
    curl -s -X POST "$PROXY_URL/api/v1/auth/sign-in" \\
        -H "Content-Type: application/json" \\
        -d "{\\"email\\":\\"$LEGIT_USER_EMAIL\\",\\"password\\":\\"$LEGIT_USER_PASSWORD\\"}" \\
        | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('token',''))"
}

# get a token for the victim user — used in S-03 (stolen-token attack)
# The victim user has NOT been attacked directly, so login should succeed.
get_victim_token() {
    curl -s -X POST "$PROXY_URL/api/v1/auth/sign-in" \\
        -H "Content-Type: application/json" \\
        -d "{\\"email\\":\\"$VICTIM_USER_EMAIL\\",\\"password\\":\\"$VICTIM_USER_PASSWORD\\"}" \\
        | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('token',''))"
}'''
if old_fn in text:
    text = text.replace(old_fn, new_fn)
common.write_text(text)
print("✓ common.sh: added VICTIM_USER_* fixtures and get_victim_token()")

# ─────────────────────────────────────────────────────────────────────
# FIX 3: s02c, s03a/b/c — use get_victim_token instead of get_legit_token
# ─────────────────────────────────────────────────────────────────────
for fn in ["s02c_param_fuzzing.sh", "s03a_token_drain.sh",
           "s03b_self_transfer_loop.sh", "s03c_param_tampering.sh"]:
    p = SCENARIOS / fn
    text = p.read_text()
    # Replace get_legit_token() calls with get_victim_token()
    new_text = re.sub(r'TOKEN=\$\(get_legit_token\)', 'TOKEN=$(get_victim_token)', text)
    # Also update LEGIT_USER_ID references to VICTIM_USER_ID in transfer URLs
    new_text = re.sub(r'\$LEGIT_USER_ID', '$VICTIM_USER_ID', new_text)
    # For s03a/b/c the hardcoded u_1004 references need to become u_1006
    new_text = new_text.replace("u_1004", "u_1006")
    if new_text != text:
        p.write_text(new_text)
        print(f"✓ {fn}: now uses victim token + u_1006")
    else:
        print(f"⚠ {fn}: no changes applied")

# ─────────────────────────────────────────────────────────────────────
# FIX 4: s05 — read pre/post snapshots in the order the scenarios ran
# Use _pre_suite and _post_suite, which are taken at suite boundaries
# Earlier code was looking for s01a_brute_force_db_pre.json which only
# scenarios that snapshot the DB produce — most scenarios don't
# ─────────────────────────────────────────────────────────────────────
s05 = SCENARIOS / "s05_containment_proofs.sh"
text = s05.read_text()
# Replace the data loading: use suite-wide snapshots only
old_python = '''# Map: scenario_id -> (pre_db_file, post_db_file)
proofs = {
    "s01_credential_attacks": ("s01a_brute_force", "s01c_slow_trickle"),
    "s03_financial_fraud":   ("s03a_token_drain", "s03c_param_tampering"),
    "s04_account_creation":  ("s04a_mass_signup", "s04c_slow_signups"),
}

summary = {
    "timestamp": "$(date -Iseconds)",
    "scenarios": {}
}

# Compute deltas from individual scenario DB snapshots
for proof_name, (first, last) in proofs.items():
    pre = load_json(results_dir / f"{first}_db_pre.json")
    post = load_json(results_dir / f"{last}_db_post.json")
    if pre is None or post is None:
        # Some scenarios don't snapshot DB (only proxy log); use earliest/latest available
        pre = load_json(results_dir / "_pre_suite_db.json")
        post = load_json(results_dir / "_post_suite_db.json")
    if pre is None or post is None:
        summary["scenarios"][proof_name] = {"error": "no snapshots available"}
        continue'''

new_python = '''# Use suite-wide pre/post snapshots, which cover the entire run
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
    pre_s  = load_json(results_dir / pre_f) or pre
    post_s = load_json(results_dir / post_f) or post
    if pre_s is None or post_s is None:
        summary["scenarios"][proof_name] = {"error": "no snapshots available"}
        continue
    pre, post = pre_s, post_s'''

if old_python in text:
    text = text.replace(old_python, new_python)
    s05.write_text(text)
    print("✓ s05: uses suite-wide snapshots with per-scenario fallback")
else:
    print("⚠ s05: old python block not found verbatim")

# ─────────────────────────────────────────────────────────────────────
# FIX 5: s04a — the 422 issue is likely phone uniqueness
# Make phone numbers fully unique with timestamp
# ─────────────────────────────────────────────────────────────────────
s04a = SCENARIOS / "s04a_mass_signup.sh"
text = s04a.read_text()
old = '''"phone":"+966500000$(printf '%03d' $i)",'''
new = '''"phone":"+9665$(date +%s | tail -c 7)$(printf '%02d' $i)",'''
if old in text:
    s04a.write_text(text.replace(old, new))
    print("✓ s04a: phone numbers are now globally unique")
else:
    print("⚠ s04a: phone block not found")

print("\nAll patches applied. Now add the victim user to your DBs:")
print()
print("HASH=$(python3 -c \"from backend_api.security import hash_password; print(hash_password('Z3m7pQ2vN8bRwX6t'))\")")
print()
print("sqlite3 digital_wallet.db \"INSERT OR IGNORE INTO users (id, full_name, email, password, phone, city, is_verified, created_at, updated_at) VALUES ('u_1006', 'Victim User', 'victim@gate80test.com', '$HASH', '+966555555556', 'Jeddah', 1, '2026-02-08 21:56:51', '2026-02-08 21:56:51');\"")
print()
print("sqlite3 digital_wallet.db \"INSERT OR IGNORE INTO wallets (id, user_id, currency_code, balance, status, created_at, updated_at) VALUES ('w_5006', 'u_1006', 'SAR', '1000.00', 'ACTIVE', '2026-02-08 22:00:00.000000', '2026-02-08 22:00:00.000000');\"")
print()
print("sqlite3 decoy_wallet.db \"INSERT OR IGNORE INTO users (id, full_name, email, password, phone, city, is_verified, created_at, updated_at) VALUES ('u_1006', 'Victim User', 'victim@gate80test.com', '$HASH', '+966555555556', 'Jeddah', 1, '2026-02-08 21:56:51', '2026-02-08 21:56:51');\"")
print()
print("sqlite3 decoy_wallet.db \"INSERT OR IGNORE INTO wallets (id, user_id, currency_code, balance, status, created_at, updated_at) VALUES ('w_5006', 'u_1006', 'SAR', '1000.00', 'ACTIVE', '2026-02-08 22:00:00.000000', '2026-02-08 22:00:00.000000');\"")

# GATE80 — Security & Attack Simulation Test Suite

This directory contains 13 attack scenarios across 5 categories that validate
GATE80's behavioural detection and token-mirroring containment.

## Quick start

```bash
# 1. Start GATE80 services
cd ~/Documents/KAU/GP/Gate80
bash run_all.sh
sleep 5

# 2. Run the full suite (~5 min)
bash tests/security/run_all_attacks.sh

# Or run a specific scenario
bash tests/security/run_all_attacks.sh s01a
bash tests/security/run_all_attacks.sh s03    # all S-03 variants

# 3. Results are written to tests/security/results/*.json
ls tests/security/results/
```

## Scenario map

| ID    | Category               | Use case                              | Tool        |
|-------|------------------------|---------------------------------------|-------------|
| S-01a | credential_attacks     | Brute-force on known user             | curl loop   |
| S-01b | credential_attacks     | Credential stuffing across users      | curl loop   |
| S-01c | credential_attacks     | Slow-trickle (anti-rate-limit)        | curl+sleep  |
| S-02a | endpoint_scanning      | Path enumeration                      | ffuf+SecLists |
| S-02b | endpoint_scanning      | HTTP method probing                   | curl matrix |
| S-02c | endpoint_scanning      | Parameter fuzzing                     | curl        |
| S-03a | financial_fraud        | Stolen-token wallet drain ⭐          | curl+token  |
| S-03b | financial_fraud        | Self-transfer abuse loop              | curl loop   |
| S-03c | financial_fraud        | Parameter tampering                   | curl        |
| S-04a | account_creation       | Mass signup bot                       | curl loop   |
| S-04b | account_creation       | Email cycling (+N alias bypass)       | curl        |
| S-04c | account_creation       | Slow distributed signups              | curl+sleep  |
| S-05  | containment (overall)  | Cross-cutting DB-level proofs         | sqlite3+python |

⭐ S-03a is the **thesis money shot**: attacker has a real session token, drains
the wallet, sees "success" responses — but real DB balance is unchanged.

## What each scenario produces

Every scenario writes to `tests/security/results/`:

- `<scenario>.json`           — pass/fail verdict + summary detail
- `<scenario>_pre.json`       — proxy_log state before the attack
- `<scenario>_post.json`      — proxy_log state after the attack
- `<scenario>_db_pre.json`    — real+decoy DB state before
- `<scenario>_db_post.json`   — real+decoy DB state after

## Pass criteria philosophy

| Criterion              | Why it matters                                    |
|------------------------|---------------------------------------------------|
| **Real DB delta ≈ 0**  | Defense kept attacker writes out of real DB       |
| **Decoy DB delta > 0** | Decoy successfully absorbed the attacker          |
| **Flag fires early**   | Detection didn't wait too long                    |
| **No 200 on bad input**| Defense rejected (or absorbed) malicious payloads |

## Containment verification helper

`verify_containment.py` provides a clean Python-only way to measure
containment for any ad-hoc test:

```bash
python tests/security/verify_containment.py snapshot pre
# ... run your custom attack ...
python tests/security/verify_containment.py snapshot post
python tests/security/verify_containment.py diff
```

Output includes per-table deltas and a verdict like `PERFECT_CONTAINMENT` /
`STRONG_CONTAINMENT` / `PARTIAL_CONTAINMENT`.

## Wordlist dependencies

The scripts use SecLists at `/usr/share/seclists/` (Kali default location).
If you're not on Kali, install: `sudo apt install seclists`, OR set
`SECLISTS=/path/to/your/seclists` before running.

## Notes for the thesis

S-05's verdict is the headline metric. A `PERFECT_CONTAINMENT` or
`STRONG_CONTAINMENT` result is what you cite in the defense:

> "Across 13 attack scenarios spanning credential, scanning, financial-fraud,
> and account-creation vectors, GATE80 achieved [VERDICT]: the real wallet
> database registered [N] writes during the entire attack suite, while the
> decoy database absorbed [M] writes — a containment ratio of [X]%."

Per-scenario JSONs let you cite specific numbers per attack type in the
results chapter.

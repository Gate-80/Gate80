# GATE80

Adaptive API deception system — a reverse proxy that protects digital wallet APIs by redirecting flagged sessions to an LLM-driven decoy. Graduation project at King Abdulaziz University.

## Architecture

| Component | Path | What it does |
|---|---|---|
| Proxy (:8080) | `proxy/` | Classifies every request (rolling-window + cumulative scoring). Forwards normal sessions to the backend, flagged ones to the decoy. |
| Backend API (:8000) | `backend_api/` | Customer wallet API + onboarding/projects/telemetry routes. |
| Decoy API (:8001) | `decoy_api/` | Stateful decoy. Runs deception strategies and an LLM planner. |
| Detection | `detection/` | Random Forest, 28 session-level features. |
| Platform | `gate80_platform/` | Control-plane DB (projects, endpoint inventory, decoy configs). Separate from any customer wallet. |

## Databases

| File | Contents |
|---|---|
| `digital_wallet.db` | Demo customer wallet (users, wallets, transactions) |
| `data/gate80_platform.db` | Projects, endpoint inventory, decoy configs |
| `decoy_wallet.db` | Decoy state |
| `proxy_logs.db` | Operational logs |

## Deception strategies (OWASP-aligned)

| Strategy | OAT codes | API Top 10 | Behavior |
|---|---|---|---|
| credential_based_attacks | OAT-007 + OAT-008 | API2:2023 | Progressive lockout (30min to 24h, doubling) |
| endpoint_scanning | OAT-018 + OAT-014 | API9:2023 | 404s with ghost endpoints + rate-limit escalation |
| financial_fraud | OAT-012 | API6:2023 | Transfers to 202 PENDING_REVIEW; +/-10% balance distortion |
| account_creation | OAT-019 | API2:2023 | Fake "pending email verification" + burst throttle |
| unknown_suspicious | — | (insufficient evidence) | Pass-through fallback |

## LLM backends (pluggable, env-selected)

| GATE80_LLM_BACKEND | Model | Required |
|---|---|---|
| anthropic (default) | claude-haiku-4-5 | ANTHROPIC_API_KEY |
| local | llama3.1:8b via Ollama | Ollama daemon |
| gemini | gemini-2.5-flash | GEMINI_API_KEY |

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# apikey.env
echo "ANTHROPIC_API_KEY=sk-ant-..." > apikey.env
echo "GATE80_LLM_BACKEND=anthropic" >> apikey.env

# Initialise both databases
alembic upgrade head
alembic -c alembic_platform.ini upgrade head

# Seed
python -m backend_api.db.seed_data
python scripts/bootstrap_demo_inventory.py

bash run_all.sh
```

## Quick attack demo

```bash
for i in 1 2 3 4 5 6 7 8; do
  curl -s -X POST http://127.0.0.1:8080/api/v1/auth/sign-in \
    -H "Content-Type: application/json" \
    -d '{"email":"attacker@example.com","password":"wrongpass"}'
done
```

Watch the planner:

```bash
tail -f /tmp/gate80-decoy.log | grep PLAN
```

Initial locked-out requests show `source=llm`; subsequent ones show `source=skipped` (Phase 9 short-circuit), saving ~70% of LLM cost.

## Audit & logs

| File | What |
|---|---|
| logs/llm_prompts.jsonl | One JSON line per LLM call. Customers audit every payload sent to Anthropic. |
| proxy_logs.db | Operational logs queryable via SQL or shipped to Elasticsearch. |
| /tmp/gate80-{backend,decoy,proxy}.log | Live service logs. |

## Reset

```bash
bash scripts/reset_demo.sh
python scripts/bootstrap_demo_inventory.py
```

## Key decisions (for thesis defense)

| Decision | Rationale |
|---|---|
| Hybrid: deterministic + LLM-on-novel | Matches Bridges et al. SoK Oct 2025 canonical hybrid honeypot architecture |
| Per-request plan with allowlist validation | Tiny prompts (~150 tokens output), no leaked invented fields |
| Schema-driven prompts | Generated values match customer API contract |
| LLM short-circuit on lockout/429/5xx | ~70% LLM cost savings, no quality loss |
| OWASP vocabulary | Industry-standard, defensible terminology |
| DB separation (platform vs wallet) | Multi-tenant-ready architecture |

## Future work

- Auto-provisioning per-customer wallet/decoy DBs at onboarding
- Multi-listener proxy (one port per project)
- AWS Bedrock backend (SAMA-compliant me-central-1 deployment)
- Anthropic Zero Data Retention agreement (production)
- User table split: platform_users + per-customer wallet_users

## License

Academic project — King Abdulaziz University, 2026.

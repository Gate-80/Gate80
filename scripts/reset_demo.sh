#!/bin/bash
#
# Wipe the demo customer wallet DB and reseed it from scratch.
#
# Why: before Phase 1B, digital_wallet.db held both wallet tables AND platform
# tables (projects, endpoint_inventory, decoy_config, proxy_config). After
# Phase 1B, the platform tables live in data/gate80_platform.db, so the copies
# in digital_wallet.db are stale. The cleanest fix is to drop digital_wallet.db
# and let init_db() rebuild it from the slimmed-down models.
#
# Does NOT touch:
#   - data/gate80_platform.db (managed by alembic_platform; stays as-is)
#   - decoy_wallet.db          (decoy state)
#   - proxy_logs.db             (operational logs)

set -e
cd "$(dirname "$0")/.."  # project root

echo "▶ Reset the demo customer wallet DB"
echo "  This will delete digital_wallet.db and re-run the wallet seed."
echo "  Platform DB, decoy DB, and proxy logs DB are NOT affected."
echo ""
read -p "Continue? [y/N] " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Aborted."
    exit 0
fi

# Make sure no service is holding the file open.
echo ""
echo "▶ If services are running, stop them first (Ctrl+C any uvicorn windows)."
echo "  Press Enter once you're sure nothing is using digital_wallet.db..."
read -r

if [ -f "digital_wallet.db" ]; then
    rm digital_wallet.db
    echo "✓ Removed digital_wallet.db"
fi

# Re-create wallet schema and seed demo data via the existing seeder.
# This calls init_db() (now wallet-only) then inserts the test rows.
python -m backend_api.db.seed_data

# Verify both DBs.
echo ""
echo "▶ Wallet DB tables (should be wallet-only now):"
sqlite3 digital_wallet.db ".tables"
echo ""
echo "▶ Platform DB tables (unchanged):"
sqlite3 data/gate80_platform.db ".tables"

echo ""
echo "✅ Reset complete. The wallet DB now contains only wallet tables."

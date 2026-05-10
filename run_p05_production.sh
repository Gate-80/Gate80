#!/bin/bash
# GATE80 — P-05 production-mode throughput benchmark.
#
# Why this exists:
#   The default run_all.sh starts uvicorn with --reload (dev mode). That
#   caps throughput well below production because uvicorn re-checks files
#   on every request. To get a representative P-05 throughput number, this
#   script restarts services without --reload, runs only the throughput
#   test, then puts dev mode back so you can keep working.
#
# Usage:
#   cd /Users/rama/Documents/KAU/GP/Gate80
#   bash run_p05_production.sh

set -u
cd "$(dirname "$0")"
PROJECT_ROOT="$(pwd)"

echo "============================================================"
echo " GATE80  P-05 production-mode throughput benchmark"
echo "============================================================"

# 1. Stop dev-mode services
echo "[1/5] Stopping current uvicorn processes..."
pkill -f "uvicorn backend_api" 2>/dev/null
pkill -f "uvicorn decoy_api"   2>/dev/null
pkill -f "uvicorn proxy.main"  2>/dev/null
sleep 3

# 2. Load env
if [ -f apikey.env ]; then
    set -a
    # shellcheck disable=SC1091
    source apikey.env
    set +a
    echo "      apikey.env loaded"
fi

# 3. Start in production mode (no --reload, single worker)
echo "[2/5] Starting services in production mode (no --reload)..."
nohup python -m uvicorn backend_api.main:app --host 127.0.0.1 --port 8000 \
    > /tmp/gate80-backend-prod.log 2>&1 &
nohup python -m uvicorn decoy_api.main:app   --host 127.0.0.1 --port 8001 \
    > /tmp/gate80-decoy-prod.log   2>&1 &
nohup python -m uvicorn proxy.main:app       --host 127.0.0.1 --port 8080 \
    > /tmp/gate80-proxy-prod.log   2>&1 &

# 4. Wait for boot and verify
echo "[3/5] Waiting for services to boot (8s)..."
sleep 8

echo "[4/5] Health checks:"
for port in 8000 8001 8080; do
    code=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${port}/health")
    if [ "$code" = "200" ]; then
        echo "      :${port}  OK"
    else
        echo "      :${port}  FAIL (got $code)"
        echo "      Aborting. Check /tmp/gate80-*-prod.log"
        exit 1
    fi
done

# 5. Run only P-05
echo "[5/5] Running P-05 (throughput) only..."
python tests/perf/perf_runner.py \
    --skip P-01 --skip P-02 --skip P-03 --skip P-04 --skip P-06

echo ""
echo "============================================================"
echo " Production-mode P-05 done."
echo " To return to dev mode (needed for ongoing work):"
echo "   pkill -f uvicorn && bash run_all.sh"
echo "============================================================"

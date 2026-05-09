#!/bin/bash
# GATE80 — start the full stack.
# Optional services (Elasticsearch, Logstash) are skipped if not installed.
# Required services (backend, decoy, proxy) always start.

set -u
cd "$(dirname "$0")"
PROJECT_ROOT="$(pwd)"

echo "Starting GATE80 full stack..."
echo "Project root: $PROJECT_ROOT"

PROXY_PORT=8080
BACKEND_PORT=8000
DECOY_PORT=8001
ES_PORT=9200

is_port_busy() {
  lsof -i :"$1" >/dev/null 2>&1
}

start_if_free() {
  local name="$1"
  local port="$2"
  local cmd="$3"
  if is_port_busy "$port"; then
    echo "  $name already running on port $port"
  else
    echo "  Starting $name on port $port..."
    eval "$cmd" &
    sleep 3
  fi
}

if [ -f apikey.env ]; then
  set -a
  source apikey.env
  set +a
  echo "Loaded apikey.env"
fi

ES_BIN="${ES_BIN:-/opt/homebrew/opt/elasticsearch-full/bin/elasticsearch}"
if [ -x "$ES_BIN" ]; then
  if is_port_busy "$ES_PORT"; then
    echo "  Elasticsearch already running on port $ES_PORT"
  else
    echo "  Starting Elasticsearch..."
    ES_JAVA_OPTS="${ES_JAVA_OPTS:--Xms1g -Xmx1g}" "$ES_BIN" >/tmp/gate80-elasticsearch.log 2>&1 &
    sleep 8
  fi
else
  echo "  Elasticsearch binary not found — skipping (optional)"
fi

if command -v logstash >/dev/null 2>&1; then
  if pgrep -f "logstash.*pipeline.conf" >/dev/null 2>&1; then
    echo "  Logstash already running"
  else
    echo "  Starting Logstash..."
    TZ=Asia/Riyadh logstash --path.data /tmp/logstash-gate80 -f "$PROJECT_ROOT/logstash/pipeline.conf" >/tmp/gate80-logstash.log 2>&1 &
    sleep 5
  fi
else
  echo "  Logstash not installed — skipping (optional)"
fi

start_if_free "Backend API" "$BACKEND_PORT" "uvicorn backend_api.main:app --reload --port $BACKEND_PORT >/tmp/gate80-backend.log 2>&1"
start_if_free "Decoy API" "$DECOY_PORT" "uvicorn decoy_api.main:app --reload --port $DECOY_PORT >/tmp/gate80-decoy.log 2>&1"
start_if_free "Proxy" "$PROXY_PORT" "uvicorn proxy.main:app --reload --port $PROXY_PORT >/tmp/gate80-proxy.log 2>&1"

echo ""
echo "GATE80 stack startup complete"
echo "  Backend API   : http://127.0.0.1:$BACKEND_PORT"
echo "  Decoy API     : http://127.0.0.1:$DECOY_PORT"
echo "  Proxy         : http://127.0.0.1:$PROXY_PORT"
echo ""
echo "Logs:"
echo "  /tmp/gate80-backend.log"
echo "  /tmp/gate80-decoy.log"
echo "  /tmp/gate80-proxy.log"
echo "  logs/llm_prompts.jsonl  (LLM audit trail)"

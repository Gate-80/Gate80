#!/bin/bash

# Always run from project root
cd "$(dirname "$0")"

echo "🚀 Starting GATE80 full stack..."

# -----------------------------
# Config
# -----------------------------
ES_BIN="/opt/homebrew/opt/elasticsearch-full/bin/elasticsearch"
#KIBANA_BIN="/opt/homebrew/opt/kibana-full/bin/kibana"

PROXY_PORT=8080
BACKEND_PORT=8000
DECOY_PORT=8001
FRONTEND_PORT=5173
ES_PORT=9200
#KIBANA_PORT=5601

# Frontend folder name
FRONTEND_DIR="/Users/wedalotibi/gate80-app"

# -----------------------------
# Helpers
# -----------------------------
is_port_busy() {
  lsof -i :"$1" >/dev/null 2>&1
}

start_if_free() {
  local name="$1"
  local port="$2"
  local cmd="$3"

  if is_port_busy "$port"; then
    echo "⚠️  $name already running on port $port"
  else
    echo "▶ Starting $name on port $port..."
    eval "$cmd" &
    sleep 3
  fi
}

# -----------------------------
# Start Elasticsearch
# -----------------------------
if is_port_busy "$ES_PORT"; then
  echo "⚠️  Elasticsearch already running on port $ES_PORT"
else
  echo "▶ Starting Elasticsearch..."
  "$ES_BIN" >/tmp/gate80-elasticsearch.log 2>&1 &
  sleep 10
fi



# -----------------------------
# Start Logstash
# -----------------------------
if pgrep -f "logstash.*pipeline.conf" >/dev/null 2>&1; then
  echo "⚠️  Logstash already running"
else
  echo "▶ Starting Logstash..."
TZ=Asia/Riyadh logstash \
--path.data /tmp/logstash-gate80 \
-f /Users/wedalotibi/RASD_adaptive-api-deception/logstash/pipeline.conf \>/tmp/gate80-logstash.log 2>&1 &
  sleep 5
fi

# -----------------------------
# Start Backend API
# -----------------------------
start_if_free "Backend API" "$BACKEND_PORT" "uvicorn backend_api.main:app --reload --port $BACKEND_PORT >/tmp/gate80-backend.log 2>&1"

# -----------------------------
# Start Decoy API
# -----------------------------
start_if_free "Decoy API" "$DECOY_PORT" "uvicorn decoy_api.main:app --reload --port $DECOY_PORT >/tmp/gate80-decoy.log 2>&1"

# -----------------------------
# Start Proxy
# -----------------------------
start_if_free "Proxy" "$PROXY_PORT" "uvicorn proxy.main:app --reload --port $PROXY_PORT >/tmp/gate80-proxy.log 2>&1"

# -----------------------------
# Start Frontend
# -----------------------------
#if is_port_busy "$FRONTEND_PORT"; then
  #echo "⚠️  Frontend already running on port $FRONTEND_PORT"
#else
  #if [ -d "$FRONTEND_DIR" ]; then
    #echo "▶ Starting Frontend..."
    #(
      #cd "$FRONTEND_DIR" || exit 1
      #npm run dev -- --host 0.0.0.0 >/tmp/gate80-frontend.log 2>&1
    #) &
    #sleep 5
  #else
    #echo "❌ Frontend folder '$FRONTEND_DIR' not found"
  #fi
#fi

echo ""
echo "✅ GATE80 stack startup complete"
echo "--------------------------------------"
echo "Backend API   : http://127.0.0.1:$BACKEND_PORT"
echo "Decoy API     : http://127.0.0.1:$DECOY_PORT"
echo "Proxy         : http://127.0.0.1:$PROXY_PORT"
echo "Elasticsearch : http://127.0.0.1:$ES_PORT"
echo "Frontend      : http://127.0.0.1:$FRONTEND_PORT"
echo ""
echo "Logs:"
echo "  /tmp/gate80-elasticsearch.log"
echo "  /tmp/gate80-logstash.log"
echo "  /tmp/gate80-backend.log"
echo "  /tmp/gate80-decoy.log"
echo "  /tmp/gate80-proxy.log"
echo "  /tmp/gate80-frontend.log"
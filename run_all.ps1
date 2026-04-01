# run_all.ps1
# Windows equivalent of run_all.sh for GATE80 project
# Generic - works for any team member on Windows
# Run from the project root: .\run_all.ps1

# -----------------------------
# Config
# -----------------------------
$BACKEND_PORT  = 8000
$DECOY_PORT    = 8001
$PROXY_PORT    = 8080
$FRONTEND_PORT = 5173
$ES_PORT       = 9200

# Auto-detect project root (wherever this script is located)
$PROJECT_ROOT  = Split-Path -Parent $MyInvocation.MyCommand.Path
$VENV_ACTIVATE = "$PROJECT_ROOT\.venv\Scripts\Activate.ps1"

# Frontend: search common locations relative to project root
$POSSIBLE_FRONTEND_PATHS = @(
    "$PROJECT_ROOT\dashboard",
    "$PROJECT_ROOT\frontend",
    "$PROJECT_ROOT\gate80-app",
    (Join-Path (Split-Path -Parent $PROJECT_ROOT) "GP2\gate80-app\gate80-app"),
    (Join-Path (Split-Path -Parent $PROJECT_ROOT) "gate80-app\gate80-app"),
    (Join-Path (Split-Path -Parent $PROJECT_ROOT) "gate80-app")
)

$FRONTEND_DIR = $null
foreach ($path in $POSSIBLE_FRONTEND_PATHS) {
    if (Test-Path "$path\package.json") {
        $FRONTEND_DIR = $path
        break
    }
}

Write-Host ""
Write-Host "🚀 Starting GATE80 full stack..." -ForegroundColor Cyan
Write-Host "📁 Project root: $PROJECT_ROOT" -ForegroundColor DarkGray
if ($FRONTEND_DIR) {
    Write-Host "📁 Frontend dir: $FRONTEND_DIR" -ForegroundColor DarkGray
} else {
    Write-Host "⚠️  Frontend folder not found automatically" -ForegroundColor DarkYellow
}
Write-Host ""

# -----------------------------
# Helper: Check if port is busy
# -----------------------------
function Is-PortBusy($port) {
    $result = netstat -ano | Select-String ":$port\s"
    return $null -ne $result
}

# -----------------------------
# Start Elasticsearch via Docker
# -----------------------------
Write-Host "▶ Checking Elasticsearch..." -ForegroundColor Yellow
$esRunning = docker ps --filter "name=elasticsearch" --filter "status=running" -q
if ($esRunning) {
    Write-Host "⚠️  Elasticsearch already running" -ForegroundColor DarkYellow
} else {
    docker rm elasticsearch 2>$null
    Write-Host "▶ Starting Elasticsearch on port $ES_PORT..." -ForegroundColor Yellow
    docker run -d --name elasticsearch `
        -p "${ES_PORT}:9200" `
        -e "discovery.type=single-node" `
        -e "xpack.security.enabled=false" `
        -e "http.cors.enabled=true" `
        -e "http.cors.allow-origin='*'" `
        -e "http.cors.allow-headers='*'" `
        -e "http.cors.allow-methods=OPTIONS,HEAD,GET,POST,PUT,DELETE" `
        elasticsearch:8.13.0 | Out-Null
    Write-Host "⏳ Waiting for Elasticsearch to start..." -ForegroundColor DarkYellow
    Start-Sleep -Seconds 15
}

# -----------------------------
# Start Backend API
# -----------------------------
if (Is-PortBusy $BACKEND_PORT) {
    Write-Host "⚠️  Backend API already running on port $BACKEND_PORT" -ForegroundColor DarkYellow
} else {
    Write-Host "▶ Starting Backend API on port $BACKEND_PORT..." -ForegroundColor Yellow
    Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PROJECT_ROOT'; & '$VENV_ACTIVATE'; uvicorn backend_api.main:app --reload --port $BACKEND_PORT"
    Start-Sleep -Seconds 3
}

# -----------------------------
# Start Decoy API
# -----------------------------
if (Is-PortBusy $DECOY_PORT) {
    Write-Host "⚠️  Decoy API already running on port $DECOY_PORT" -ForegroundColor DarkYellow
} else {
    Write-Host "▶ Starting Decoy API on port $DECOY_PORT..." -ForegroundColor Yellow
    Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PROJECT_ROOT'; & '$VENV_ACTIVATE'; uvicorn decoy_api.main:app --reload --port $DECOY_PORT"
    Start-Sleep -Seconds 3
}

# -----------------------------
# Start Proxy
# -----------------------------
if (Is-PortBusy $PROXY_PORT) {
    Write-Host "⚠️  Proxy already running on port $PROXY_PORT" -ForegroundColor DarkYellow
} else {
    Write-Host "▶ Starting Proxy on port $PROXY_PORT..." -ForegroundColor Yellow
    Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$PROJECT_ROOT'; & '$VENV_ACTIVATE'; uvicorn proxy.main:app --reload --port $PROXY_PORT"
    Start-Sleep -Seconds 3
}

# -----------------------------
# Sync data to Elasticsearch
# -----------------------------
$SYNC_SCRIPT = "$PROJECT_ROOT\sync_to_es_fixed.py"
if (Test-Path $SYNC_SCRIPT) {
    Write-Host "▶ Syncing data to Elasticsearch..." -ForegroundColor Yellow
    & "$PROJECT_ROOT\.venv\Scripts\python.exe" $SYNC_SCRIPT
    Write-Host "✅ Sync complete" -ForegroundColor Green
} else {
    Write-Host "⚠️  sync_to_es_fixed.py not found, skipping sync" -ForegroundColor DarkYellow
}

# -----------------------------
# Start Frontend
# -----------------------------
if (Is-PortBusy $FRONTEND_PORT) {
    Write-Host "⚠️  Frontend already running on port $FRONTEND_PORT" -ForegroundColor DarkYellow
} elseif ($FRONTEND_DIR) {
    Write-Host "▶ Starting Frontend on port $FRONTEND_PORT..." -ForegroundColor Yellow
    Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$FRONTEND_DIR'; npm run dev"
    Start-Sleep -Seconds 5
} else {
    Write-Host "❌ Could not find frontend folder. Please set it manually in this script." -ForegroundColor Red
}

# -----------------------------
# Summary
# -----------------------------
Write-Host ""
Write-Host "✅ GATE80 stack startup complete" -ForegroundColor Green
Write-Host "--------------------------------------"
Write-Host "Backend API   : http://127.0.0.1:$BACKEND_PORT"
Write-Host "Decoy API     : http://127.0.0.1:$DECOY_PORT"
Write-Host "Proxy         : http://127.0.0.1:$PROXY_PORT"
Write-Host "Elasticsearch : http://127.0.0.1:$ES_PORT"
Write-Host "Frontend      : http://localhost:$FRONTEND_PORT"
Write-Host ""
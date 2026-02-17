# proxy/main.py
from fastapi import FastAPI, Request
from fastapi.responses import Response
import httpx
import time, uuid

# Disable Swagger UI on proxy - it's just a transparent forwarder
app = FastAPI(
    docs_url=None,      # Disable /docs
    redoc_url=None,     # Disable /redoc
    openapi_url=None    # Disable /openapi.json
)

BACKEND_URL = "http://127.0.0.1:8000"

HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-length",
}

# implenting logging
@app.middleware("http")
async def log_requests(request: Request, call_next):
    req_id = request.headers.get("X-Request-Id") or str(uuid.uuid4())
    start = time.time()
    response = await call_next(request)
    ms = int((time.time() - start) * 1000)
    print(f"[proxy] id={req_id} {request.method} {request.url.path} -> {response.status_code} {ms}ms")
    response.headers["X-Request-Id"] = req_id
    return response




@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
async def reverse_proxy(request: Request, path: str):

    target_url = f"{BACKEND_URL}/{path}"

    body = await request.body()

    async with httpx.AsyncClient() as client:
        backend_response = await client.request(
            method=request.method,
            url=target_url,
            params=request.query_params,
            content=body,
          headers={
             k: v
             for k, v in request.headers.items()
              if k.lower() != "host" and k.lower() not in HOP_BY_HOP_HEADERS
            } | {"X-From-Proxy": "1"},

        )

    return Response(
        content=backend_response.content,
        status_code=backend_response.status_code,
        headers=dict(backend_response.headers),
    )

from fastapi import FastAPI, Request
from fastapi.responses import Response
import httpx

app = FastAPI()

BACKEND_URL = "http://127.0.0.1:8000"

@app.api_route("/{path:path}", methods=["GET", "POST", "PATCH", "DELETE"])
async def reverse_proxy(request: Request, path: str):

    target_url = f"{BACKEND_URL}/{path}"

    body = await request.body()

    async with httpx.AsyncClient() as client:
        backend_response = await client.request(
            method=request.method,
            url=target_url,
            params=request.query_params,
            content=body,
            headers={k: v for k, v in request.headers.items() if k.lower() != "host"},
        )

    return Response(
        content=backend_response.content,
        status_code=backend_response.status_code,
        headers=dict(backend_response.headers),
    )

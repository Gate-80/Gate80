import time
from fastapi.responses import JSONResponse

def build_decoy_response(decoy_config: dict):
    delay_ms = decoy_config.get("delay_ms", 0)
    if delay_ms > 0:
        time.sleep(delay_ms / 1000)

    return JSONResponse(
        status_code=decoy_config.get("status_code", 200),
        content={
            "decoy": True,
            "strategy": decoy_config.get("strategy", "generic_decoy"),
            "message": decoy_config.get("message", "Request processed")
        }
    )
import json
import time
from fastapi.responses import JSONResponse


def build_decoy_response(decoy_config: dict):
    delay_ms = decoy_config.get("delay_ms", 0)
    if delay_ms > 0:
        time.sleep(delay_ms / 1000)

    status_code = decoy_config.get("status_code", 200)
    body = decoy_config.get("response_template")

    if isinstance(body, str):
        try:
            body = json.loads(body)
        except Exception:
            body = {"message": body}

    if not body:
        decoy_type = decoy_config.get("decoy_type", "generic")
        if decoy_type == "fake_failure":
            body = {"detail": "Invalid credentials"}
        elif decoy_type == "fake_success":
            body = {"message": "Request accepted"}
        elif decoy_type == "delayed_response":
            body = {"message": "Processing request"}
        elif decoy_type == "honey_data":
            body = {"message": "Resource found", "items": []}
        else:
            body = {"message": "Request processed"}

    return JSONResponse(status_code=status_code, content=body)
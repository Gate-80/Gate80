from __future__ import annotations
import json
import yaml
from typing import Any, Dict, List


def load_openapi_document(raw_text: str) -> Dict[str, Any]:
    try:
        return json.loads(raw_text)
    except json.JSONDecodeError:
        return yaml.safe_load(raw_text)


def parse_openapi_endpoints(spec: Dict[str, Any]) -> List[Dict[str, Any]]:
    paths = spec.get("paths", {})
    endpoints: List[Dict[str, Any]] = []

    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue

        for method, operation in methods.items():
            if method.lower() not in {
                "get", "post", "put", "delete", "patch", "options", "head"
            }:
                continue

            operation = operation or {}
            tags = operation.get("tags", [])
            summary = operation.get("summary", "")
            security = operation.get("security", spec.get("security", []))
            requires_auth = bool(security)

            request_schema = {}
            request_body = operation.get("requestBody", {})
            content = request_body.get("content", {})
            if "application/json" in content:
                request_schema = content["application/json"].get("schema", {})

            response_schema = {}
            responses = operation.get("responses", {})
            for code, response in responses.items():
                response_content = response.get("content", {})
                if "application/json" in response_content:
                    response_schema = response_content["application/json"].get("schema", {})
                    break

            endpoints.append({
                "path": path,
                "method": method.upper(),
                "summary": summary,
                "tag": tags[0] if tags else "uncategorized",
                "requires_auth": requires_auth,
                "request_schema_json": request_schema,
                "response_schema_json": response_schema,
            })

    return endpoints
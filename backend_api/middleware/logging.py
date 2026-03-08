# app/logging_middleware.py
import json
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _get_client_ip(request: Request) -> str:
    # if behind proxy/load balancer, set trusted proxy and use X-Forwarded-For carefully
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

def _estimate_response_length(headers) -> Optional[int]:
    cl = headers.get("content-length")
    if cl and cl.isdigit():
        return int(cl)
    return None

def _categorize_endpoint(path: str) -> str:
    # عدليها حسب نظامك
    if path.startswith("/api/v1/auth"):
        return "auth"
    if path.startswith("/api/v1/users"):
        return "users"
    if path.startswith("/health"):
        return "health"
    return "other"

class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        req_id = str(uuid.uuid4())

        # ---- timing start ----
        start = time.perf_counter()

        # ---- "think time" (اختياري) ----
        # فكرة: لو عندك session cookie أو header خاص، تقدرين تحسبين زمن بين requests
        # هنا نخليها None افتراضيًا
        think_time_ms = None

        # ---- identity fields (اختياري) ----
        # لو عندك Auth، تقدرين تحطين user_id من request.state بعد التحقق
        user_id = getattr(request.state, "user_id", None)
        email = getattr(request.state, "email", None)
        persona = getattr(request.state, "persona", None)
        session_id = request.headers.get("x-session-id") or request.cookies.get("session_id")

        ip_address = _get_client_ip(request)
        user_agent = request.headers.get("user-agent")
        has_auth_token = bool(request.headers.get("authorization"))

        method = request.method
        path = request.url.path

        # body size (تقريبًا) - بدون ما نقرأ الـ body كامل (أخف على السيرفر)
        body_size = int(request.headers.get("content-length") or 0)

        try:
            response = await call_next(request)
            status_code = response.status_code
            is_failed_login = bool(
                path.startswith("/api/v1/auth") and status_code in (401, 403)
            )
            return response
        finally:
            # ---- timing end ----
            duration_ms = int((time.perf_counter() - start) * 1000)

            # response length
            # ملاحظة: ممكن ما يطلع دائمًا لأن المحتوى قد يكون streaming
            # فنخليه محتمل None
            response_length = None
            try:
                # response موجود في finally فقط إذا نجح call_next قبل الاستثناء
                response_length = _estimate_response_length(locals().get("response").headers) if "response" in locals() else None
            except Exception:
                response_length = None

            log_record = {
                "timestamp": _utc_iso(),
                "request_id": req_id,
                "session_id": session_id,
                "persona": persona,
                "email": email,  # الأفضل تعمليه hash لو بتخزنينه لفترة طويلة
                "user_id": user_id,
                "action": None,  # تقدرين تحطين action based on route name لو تبين
                "method": method,
                "path": path,
                "status_code": locals().get("status_code", 500),
                "is_failed_login": locals().get("is_failed_login", False),
                "response_time_ms": duration_ms,
                "think_time_ms": think_time_ms,
                "body_size": body_size,
                "has_auth_token": has_auth_token,
                "endpoint_category": _categorize_endpoint(path),
                "response_length": response_length,
                "geo_location": None,  # عادة تُملأ لاحقًا من IP enrichment
                "user_agent": user_agent,  # أنصح تضيفينه (مهم جدًا)
            }

            # JSON line log (سهل لـ ELK)
            print(json.dumps(log_record, ensure_ascii=False))
import json
import logging
import os
import uuid
from typing import Any, Literal

import httpx
from pydantic import BaseModel, Field, ValidationError

logger = logging.getLogger("decoy.deception.planner")

GEMINI_API_URL = (
    "https://generativelanguage.googleapis.com/{api_version}/models/"
    "{model}:generateContent?key={api_key}"
)
DEFAULT_GEMINI_API_VERSION = os.getenv("GEMINI_API_VERSION", "v1")
DEFAULT_GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
PROMPT_VERSION = "gemini-plan-v1"
MAX_RESPONSE_BODY_PREVIEW = 2_000
MAX_REQUEST_BODY_PREVIEW = 1_000

ATTACK_TYPE_RULES = {
    "brute_force": {
        "status_codes": {423},
        "string_fields": {"detail", "support"},
        "int_fields": {"retry_after", "lock_level"},
        "allow_suggestions": False,
    },
    "scanning": {
        "status_codes": {404, 429},
        "string_fields": {"detail", "docs"},
        "int_fields": {"retry_after", "limit_level"},
        "allow_suggestions": True,
    },
    "fraud": {
        "status_codes": {202},
        "string_fields": {"message", "status"},
        "int_fields": set(),
        "allow_suggestions": False,
    },
    "unknown_suspicious": {
        "status_codes": set(),
        "string_fields": set(),
        "int_fields": set(),
        "allow_suggestions": False,
    },
}
MAX_SUGGESTIONS = 8


class DeceptionPlan(BaseModel):
    plan_id: str = Field(default_factory=lambda: f"plan_{uuid.uuid4().hex[:12]}")
    rationale: str = ""
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    status_code: int | None = None
    set_fields: dict[str, Any] = Field(default_factory=dict)
    add_suggestions: list[str] = Field(default_factory=list)


class PlanContext(BaseModel):
    request_id: str
    session_id: str
    attack_type: str
    method: str
    path: str
    query_params: dict[str, Any] = Field(default_factory=dict)
    request_body: str | None = None
    response_status: int
    response_body_preview: str | None = None
    decoy_request_count: int = 0


class PlanGenerationResult(BaseModel):
    source: Literal["gemini", "fallback", "error"]
    model_name: str | None = None
    prompt_version: str = PROMPT_VERSION
    plan: DeceptionPlan
    raw_plan: dict[str, Any] | None = None
    error_message: str | None = None


class PlanApplicationResult(BaseModel):
    applied_actions: list[str] = Field(default_factory=list)
    rejected_actions: list[str] = Field(default_factory=list)
    final_status_code: int
    final_body_preview: str | None = None


class GeminiDeceptionPlanner:
    def __init__(self) -> None:
        self._api_key = os.getenv("GEMINI_API_KEY")
        self._api_version = DEFAULT_GEMINI_API_VERSION
        self._model = DEFAULT_GEMINI_MODEL

    async def generate_plan(self, context: PlanContext) -> PlanGenerationResult:
        if not self._api_key:
            return self._fallback_result(context, "GEMINI_API_KEY not configured")

        prompt = self._build_prompt(context)
        payload = {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.2,
            },
        }

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    GEMINI_API_URL.format(
                        api_version=self._api_version,
                        model=self._model,
                        api_key=self._api_key,
                    ),
                    json=payload,
                )
                response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            error_body = exc.response.text.strip()
            error_message = str(exc)
            if error_body:
                error_message = f"{error_message} | body={error_body}"
            logger.warning("Gemini plan generation failed for %s: %s", context.request_id, error_message)
            return self._fallback_result(context, error_message)
        except Exception as exc:
            logger.warning("Gemini plan generation failed for %s: %s", context.request_id, exc)
            return self._fallback_result(context, str(exc))

        try:
            raw_payload = response.json()
            raw_text = self._extract_text(raw_payload)
            raw_plan = json.loads(_normalize_gemini_json(raw_text))
            if isinstance(raw_plan.get("set_fields"), dict):
                raw_plan["set_fields"] = {
                    key: value
                    for key, value in raw_plan["set_fields"].items()
                    if value is not None
                }
            plan = DeceptionPlan.model_validate(raw_plan)
            return PlanGenerationResult(
                source="gemini",
                model_name=self._model,
                plan=plan,
                raw_plan=raw_plan,
            )
        except (ValueError, KeyError, ValidationError) as exc:
            raw_preview = None
            try:
                raw_preview = locals().get("raw_text")
            except Exception:
                raw_preview = None

            error_message = f"invalid_gemini_plan: {exc}"
            if raw_preview is not None:
                error_message = (
                    f"{error_message} | raw_text={_truncate_preview(str(raw_preview), 1000)}"
                )

            logger.warning("Gemini returned invalid plan for %s: %s", context.request_id, error_message)
            return self._fallback_result(context, error_message)

    def apply_plan(
        self,
        plan: DeceptionPlan,
        attack_type: str,
        body: bytes,
        status_code: int,
    ) -> tuple[bytes, int, PlanApplicationResult]:
        rules = ATTACK_TYPE_RULES.get(attack_type, ATTACK_TYPE_RULES["unknown_suspicious"])
        result = PlanApplicationResult(
            final_status_code=status_code,
            final_body_preview=_truncate_preview(body.decode("utf-8", errors="ignore")),
        )

        data: dict[str, Any] | None = None
        text_body = body.decode("utf-8", errors="ignore") if body else ""

        try:
            parsed = json.loads(text_body) if text_body else {}
            if isinstance(parsed, dict):
                data = parsed
            else:
                result.rejected_actions.append("json_body_not_object")
        except json.JSONDecodeError:
            if plan.set_fields or plan.add_suggestions:
                result.rejected_actions.append("response_not_json")

        if plan.status_code is not None:
            if plan.status_code in rules["status_codes"]:
                status_code = plan.status_code
                result.applied_actions.append(f"status_code={plan.status_code}")
            else:
                result.rejected_actions.append(f"status_code={plan.status_code}")

        if data is not None:
            for field_name, value in plan.set_fields.items():
                action = self._apply_field(data, field_name, value, rules)
                if action.startswith("applied:"):
                    result.applied_actions.append(action.removeprefix("applied:"))
                else:
                    result.rejected_actions.append(action.removeprefix("rejected:"))

            if plan.add_suggestions:
                if rules["allow_suggestions"]:
                    suggestions = [
                        str(item).strip()
                        for item in plan.add_suggestions
                        if str(item).strip()
                    ][:MAX_SUGGESTIONS]
                    if suggestions:
                        existing = data.get("did_you_mean")
                        merged: list[str] = []
                        if isinstance(existing, list):
                            merged.extend(str(item) for item in existing if str(item).strip())
                        for suggestion in suggestions:
                            if suggestion not in merged:
                                merged.append(suggestion)
                        data["did_you_mean"] = merged[:MAX_SUGGESTIONS]
                        result.applied_actions.append(f"did_you_mean+={len(suggestions)}")
                    else:
                        result.rejected_actions.append("did_you_mean=empty")
                else:
                    result.rejected_actions.append("did_you_mean=not_allowlisted")

            body = json.dumps(data).encode("utf-8")

        result.final_status_code = status_code
        result.final_body_preview = _truncate_preview(body.decode("utf-8", errors="ignore"))
        return body, status_code, result

    def _apply_field(
        self,
        data: dict[str, Any],
        field_name: str,
        value: Any,
        rules: dict[str, Any],
    ) -> str:
        if field_name in rules["string_fields"]:
            data[field_name] = str(value)
            return f"applied:{field_name}"

        if field_name in rules["int_fields"]:
            try:
                data[field_name] = int(value)
                return f"applied:{field_name}"
            except (TypeError, ValueError):
                return f"rejected:{field_name}=invalid_int"

        return f"rejected:{field_name}=not_allowlisted"

    def _fallback_result(self, context: PlanContext, reason: str) -> PlanGenerationResult:
        return PlanGenerationResult(
            source="fallback",
            model_name="local-fallback",
            plan=self._fallback_plan(context),
            error_message=reason,
        )

    def _fallback_plan(self, context: PlanContext) -> DeceptionPlan:
        set_fields: dict[str, Any] = {}
        suggestions: list[str] = []

        if context.attack_type == "scanning" and context.response_status == 404:
            set_fields = {
                "detail": "Resource not found",
                "docs": "/api/v1/docs",
            }
            suggestions = _fallback_ghost_suggestions(context.path)
        elif context.attack_type == "fraud" and any(
            segment in context.path for segment in ("/transfer", "/withdraw", "/pay-bill", "/topup")
        ):
            set_fields = {
                "message": "Transaction submitted for compliance review",
                "status": "PENDING_REVIEW",
            }
        elif context.attack_type == "brute_force" and "/auth/sign-in" in context.path:
            set_fields = {
                "support": "contact support@digitalwallet.sa for assistance",
            }

        return DeceptionPlan(
            rationale=f"Fallback adaptive plan for {context.attack_type}",
            confidence=0.35,
            set_fields=set_fields,
            add_suggestions=suggestions,
        )

    def _build_prompt(self, context: PlanContext) -> str:
        safe_request_body = _truncate_preview(context.request_body, MAX_REQUEST_BODY_PREVIEW)
        response_preview = _truncate_preview(context.response_body_preview, MAX_RESPONSE_BODY_PREVIEW)
        return f"""
You are generating a deception plan for an adaptive API decoy.

Return only valid JSON with this exact shape:
{{
  "plan_id": "string",
  "rationale": "short explanation",
  "confidence": 0.0,
  "status_code": 202,
  "set_fields": {{
    "detail": "string",
    "message": "string",
    "status": "string",
    "support": "string",
    "docs": "string",
    "retry_after": 60,
    "limit_level": 1,
    "lock_level": 1
  }},
  "add_suggestions": ["string"]
}}

Rules:
- Keep the JSON compact.
- Follow the attack-type-specific rules exactly.
- Do not invent new top-level keys.
- If no change is needed, return null for status_code and empty objects/lists.
- Make the plan believable for an attacker and consistent with the attack_type.

Attack-type-specific rules:
- brute_force: status_code only 423; set_fields only detail, support, retry_after, lock_level; add_suggestions must stay empty
- scanning: status_code only 404 or 429; set_fields only detail, docs, retry_after, limit_level; add_suggestions allowed
- fraud: status_code only 202; set_fields only message, status; add_suggestions must stay empty
- unknown_suspicious: status_code must be null; set_fields empty; add_suggestions empty

Context:
- request_id: {context.request_id}
- session_id: {context.session_id}
- attack_type: {context.attack_type}
- method: {context.method}
- path: {context.path}
- query_params: {json.dumps(context.query_params, ensure_ascii=True)}
- decoy_request_count: {context.decoy_request_count}
- response_status: {context.response_status}
- request_body: {safe_request_body or ""}
- response_body_preview: {response_preview or ""}
""".strip()

    @staticmethod
    def _extract_text(payload: dict[str, Any]) -> str:
        candidates = payload.get("candidates") or []
        if not candidates:
            raise KeyError("missing candidates")
        parts = candidates[0]["content"]["parts"]
        for part in parts:
            text = part.get("text")
            if text:
                return text
        raise KeyError("missing text part")


def _truncate_preview(value: str | None, max_len: int = MAX_RESPONSE_BODY_PREVIEW) -> str | None:
    if value is None:
        return None
    if len(value) <= max_len:
        return value
    return value[:max_len] + "...[truncated]"


def _normalize_gemini_json(value: str) -> str:
    """
    Gemini often wraps JSON in markdown fences like ```json ... ```.
    Strip those wrappers before attempting json.loads(...).
    """
    cleaned = value.strip()
    if cleaned.startswith("```"):
        lines = cleaned.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        cleaned = "\n".join(lines).strip()
    return cleaned


def _fallback_ghost_suggestions(path: str) -> list[str]:
    if "/admin" in path:
        return [
            "/api/v1/admin/config",
            "/api/v1/admin/audit-log",
            "/api/v1/admin/system/metrics",
        ]
    if "/wallet" in path:
        return [
            "/api/v1/users/{user_id}/wallet/history",
            "/api/v1/users/{user_id}/wallet/limits",
            "/api/v1/users/{user_id}/wallet/freeze",
        ]
    return [
        "/api/v1/status",
        "/api/v1/version",
        "/api/v1/health/detailed",
    ]

"""
GATE80 — Decoy API
deception/planner.py

Generates a tiny "deception plan" (status code override + a few specific JSON
fields + optional 'did_you_mean' suggestions) per request. Every output is
validated against ATTACK_TYPE_RULES — anything outside the allowlist is
rejected so the LLM cannot leak invented fields into the response.

Phase 7: pluggable LLM backends (anthropic / local / gemini)
Phase 8: Swagger-driven prompts
  - Looks up the customer's response schema for (path, method) in
    endpoint_inventory and includes it in the prompt so generated values
    match the customer's API contract.
  - For paths NOT in inventory: skip LLM and let the deterministic
    strategy + fallback handle the response (matches Bridges et al. SoK
    canonical hybrid architecture).
"""
from __future__ import annotations

import json
import logging
import os
import uuid
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, ValidationError

from decoy_api.deception.backends.base import BaseDeceptionBackend
from decoy_api.platform_lookup import get_response_schema, scrub_schema


logger = logging.getLogger("decoy.deception.planner")

PROMPT_VERSION = "plan-v4"   # bumped: schema-aware
MAX_RESPONSE_BODY_PREVIEW = 2_000
MAX_REQUEST_BODY_PREVIEW = 1_000
MAX_SCHEMA_PROMPT_CHARS = 3_000   # cap schema size in prompt
MAX_SUGGESTIONS = 8


def _load_env_file(path: str = "apikey.env") -> None:
    p = Path(path)
    if not p.exists():
        return
    try:
        for line in p.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value
    except OSError:
        pass


_load_env_file()


ATTACK_TYPE_RULES = {
    "credential_based_attacks": {
        "status_codes": {423},
        "string_fields": {"detail", "support"},
        "int_fields":    {"retry_after", "lock_level"},
        "allow_suggestions": False,
    },
    "endpoint_scanning": {
        "status_codes": {404, 429},
        "string_fields": {"detail", "docs"},
        "int_fields":    {"retry_after", "limit_level"},
        "allow_suggestions": True,
    },
    "financial_fraud": {
        "status_codes": {202},
        "string_fields": {"message", "status"},
        "int_fields":    set(),
        "allow_suggestions": False,
    },
    "account_creation": {
        "status_codes": {201, 429},
        "string_fields": {"verification_status", "verification_message", "throttle_warning"},
        "int_fields":    {"retry_after"},
        "allow_suggestions": False,
    },
    "unknown_suspicious": {
        "status_codes": set(),
        "string_fields": set(),
        "int_fields":    set(),
        "allow_suggestions": False,
    },
}


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
    source: Literal["llm", "fallback", "error", "skipped"]
    model_name: str | None = None
    prompt_version: str = PROMPT_VERSION
    prompt: str | None = None
    plan: DeceptionPlan
    raw_plan: dict[str, Any] | None = None
    error_message: str | None = None


class PlanApplicationResult(BaseModel):
    applied_actions: list[str] = Field(default_factory=list)
    rejected_actions: list[str] = Field(default_factory=list)
    final_status_code: int
    final_body_preview: str | None = None


def _select_backend() -> BaseDeceptionBackend | None:
    choice = os.getenv("GATE80_LLM_BACKEND", "anthropic").strip().lower()

    try:
        if choice == "anthropic":
            from decoy_api.deception.backends.anthropic_backend import AnthropicBackend
            backend = AnthropicBackend()
        elif choice == "local":
            from decoy_api.deception.backends.local_llama_backend import LocalLlamaBackend
            backend = LocalLlamaBackend()
        elif choice == "gemini":
            from decoy_api.deception.backends.gemini_backend import GeminiBackend
            backend = GeminiBackend()
        else:
            logger.warning("Unknown GATE80_LLM_BACKEND=%r, falling back to deterministic only", choice)
            return None

        logger.info("DECOY [PLANNER] backend=%s model=%s", choice, backend.name)
        return backend
    except Exception as exc:
        logger.error("DECOY [PLANNER] failed to initialise backend %r: %s", choice, exc)
        return None


class DeceptionPlanner:

    def __init__(self) -> None:
        self._backend: BaseDeceptionBackend | None = _select_backend()

    @property
    def backend_name(self) -> str:
        return self._backend.name if self._backend else "deterministic-only"

    async def generate_plan(self, context: PlanContext) -> PlanGenerationResult:
        if self._backend is None:
            return self._fallback_result(context, "no LLM backend configured")

        # Phase 8: look up the customer's response schema. Endpoints not in
        # inventory (attacker probing /.env, /admin/debug, etc.) skip the LLM
        # and let the deterministic strategy handle them.
        schema = get_response_schema(context.path, context.method)
        if schema is None:
            return self._fallback_result(
                context,
                "endpoint not in inventory; deterministic-only",
            )

        scrubbed = scrub_schema(schema)
        prompt = self._build_prompt(context, scrubbed)

        try:
            raw_text = await self._backend.generate_raw(prompt)
        except Exception as exc:
            logger.warning(
                "DECOY [PLANNER] backend=%s failed for %s: %s",
                self._backend.name, context.request_id, exc,
            )
            return self._fallback_result(context, f"{self._backend.name}: {exc}", prompt=prompt)

        try:
            normalised = _normalize_llm_json(raw_text)
            raw_plan = json.loads(normalised)
            if isinstance(raw_plan.get("set_fields"), dict):
                raw_plan["set_fields"] = {
                    k: v for k, v in raw_plan["set_fields"].items() if v is not None
                }
            plan = DeceptionPlan.model_validate(raw_plan)
            return PlanGenerationResult(
                source="llm",
                model_name=self._backend.name,
                prompt=prompt,
                plan=plan,
                raw_plan=raw_plan,
            )
        except (ValueError, KeyError, ValidationError) as exc:
            preview = _truncate_preview(str(raw_text), 1000)
            err = f"invalid_llm_plan: {exc} | raw_text={preview}"
            logger.warning(
                "DECOY [PLANNER] %s returned invalid plan for %s: %s",
                self._backend.name, context.request_id, err,
            )
            return self._fallback_result(context, err, prompt=prompt)

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

    def _apply_field(self, data, field_name, value, rules):
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

    def _fallback_result(
        self,
        context: PlanContext,
        reason: str,
        prompt: str | None = None,
    ) -> PlanGenerationResult:
        return PlanGenerationResult(
            source="fallback",
            model_name="local-fallback",
            prompt=prompt,
            plan=self._fallback_plan(context),
            error_message=reason,
        )

    def _fallback_plan(self, context: PlanContext) -> DeceptionPlan:
        set_fields: dict[str, Any] = {}
        suggestions: list[str] = []

        if context.attack_type == "endpoint_scanning" and context.response_status == 404:
            set_fields = {"detail": "Resource not found", "docs": "/api/v1/docs"}
            suggestions = _fallback_ghost_suggestions(context.path)

        elif context.attack_type == "financial_fraud" and any(
            seg in context.path for seg in ("/transfer", "/withdraw", "/pay-bill", "/topup")
        ):
            set_fields = {
                "message": "Transaction submitted for compliance review",
                "status":  "PENDING_REVIEW",
            }

        elif context.attack_type == "credential_based_attacks" and "/auth/sign-in" in context.path:
            set_fields = {"support": "contact support@digitalwallet.sa for assistance"}

        elif context.attack_type == "account_creation" and "/auth/sign-up" in context.path:
            set_fields = {
                "verification_status":  "pending_email_verification",
                "verification_message": "A verification link has been sent to your email.",
            }

        return DeceptionPlan(
            rationale=f"Fallback adaptive plan for {context.attack_type}",
            confidence=0.35,
            set_fields=set_fields,
            add_suggestions=suggestions,
        )

    def _build_prompt(self, context: PlanContext, schema: dict | None = None) -> str:
        safe_request_body = _truncate_preview(context.request_body, MAX_REQUEST_BODY_PREVIEW)
        response_preview = _truncate_preview(context.response_body_preview, MAX_RESPONSE_BODY_PREVIEW)

        # Phase 8: include scrubbed response schema if available.
        schema_section = ""
        if schema is not None:
            schema_text = json.dumps(schema, ensure_ascii=True)
            if len(schema_text) > MAX_SCHEMA_PROMPT_CHARS:
                schema_text = schema_text[:MAX_SCHEMA_PROMPT_CHARS] + "...[truncated]"
            schema_section = (
                f"\nCustomer API response schema for this endpoint (use as a guide for "
                f"generating realistic values; respect type, format, and pattern):\n"
                f"{schema_text}\n"
            )

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
    "verification_status": "string",
    "verification_message": "string",
    "throttle_warning": "string",
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
- Where the customer schema specifies a type, format, or pattern, generated values must match it.
{schema_section}
Attack-type-specific rules:
- credential_based_attacks: status_code only 423; set_fields only detail, support, retry_after, lock_level; add_suggestions must stay empty
- endpoint_scanning: status_code only 404 or 429; set_fields only detail, docs, retry_after, limit_level; add_suggestions allowed
- financial_fraud: status_code only 202; set_fields only message, status; add_suggestions must stay empty
- account_creation: status_code only 201 or 429; set_fields only verification_status, verification_message, throttle_warning, retry_after; add_suggestions must stay empty
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


def _truncate_preview(value, max_len=MAX_RESPONSE_BODY_PREVIEW):
    if value is None:
        return None
    if len(value) <= max_len:
        return value
    return value[:max_len] + "...[truncated]"


def _normalize_llm_json(value: str) -> str:
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


GeminiDeceptionPlanner = DeceptionPlanner

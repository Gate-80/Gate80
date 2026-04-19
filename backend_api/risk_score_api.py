from __future__ import annotations


HIGH_RISK_KEYWORDS = {
    "login", "signin", "sign-in", "auth", "password", "reset",
    "transfer", "withdraw", "payment", "pay", "bill",
    "wallet", "admin", "token", "otp", "verify"
}

LOW_RISK_KEYWORDS = {
    "health", "hello", "status", "ping", "docs", "swagger", "openapi"
}


def score_endpoint(path: str, method: str, tag: str, requires_auth: bool) -> tuple[int, str]:
    score = 0
    target = f"{method} {path} {tag}".lower()

    for word in HIGH_RISK_KEYWORDS:
        if word in target:
            score += 25

    for word in LOW_RISK_KEYWORDS:
        if word in target:
            score -= 20

    if requires_auth:
        score += 10

    if method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
        score += 10

    score = max(score, 0)

    if score >= 40:
        return score, "high"
    if score >= 15:
        return score, "medium"
    return score, "low"

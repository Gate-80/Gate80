"""
GATE80 — Proxy
behaviour_class.py

Two-layer behavior classification:

  Layer 1 — Sliding window (last BEHAVIOR_WINDOW_SIZE requests)
    Captures what the attacker is doing RIGHT NOW.
    Sensitive to recent behavior shifts.

  Layer 2 — Cumulative scores (entire session lifetime)
    Captures what the attacker has done THROUGHOUT the session.
    Evidence decays by DECAY_RATE per request so old signals
    contribute less over time but never vanish entirely.

  Final classification:
    combined = WINDOW_WEIGHT × window_score + CUMULATIVE_WEIGHT × cumulative_score
    Picks category with highest combined score.
    Requires CONFIDENCE_MARGIN gap to commit — otherwise unknown_suspicious.

Decay rate = 0.85 per request. Window size = 6.

Phase 6: category vocabulary aligned with the OWASP attack-type table.
  Returns one of:
    "credential_based_attacks"  (OAT-007 + OAT-008, API2:2023)
    "endpoint_scanning"         (OAT-018 + OAT-014, API9:2023)
    "financial_fraud"           (OAT-012, API6:2023)
    "account_creation"          (OAT-019, API2:2023)
    "unknown_suspicious"        (insufficient evidence to commit)
"""

import time
from collections import deque
from dataclasses import dataclass, field


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

# p25 of total_requests in baseline_sessions.csv (426 normal sessions)
BEHAVIOR_WINDOW_SIZE = 6

# Decay factor applied to cumulative scores on each new request.
# 0.85 derived from baseline session length distribution.
DECAY_RATE = 0.85

# Weighted combination of window and cumulative scores
WINDOW_WEIGHT     = 0.6
CUMULATIVE_WEIGHT = 0.4

# Minimum score gap between winner and second place.
# If gap < CONFIDENCE_MARGIN → unknown_suspicious.
CONFIDENCE_MARGIN = 1

# Attack categories (OWASP-aligned vocabulary)
CATEGORIES = [
    "credential_based_attacks",
    "endpoint_scanning",
    "financial_fraud",
    "account_creation",
]


# ─────────────────────────────────────────────────────────────────────────────
# Per-request signal
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class RequestSignal:
    """Lightweight behavioral record for one request."""
    timestamp:     float
    path:          str
    status_code:   int
    think_time_ms: float
    method:        str = "GET"

    @property
    def is_error(self) -> bool:
        return self.status_code >= 400

    @property
    def is_auth_error(self) -> bool:
        return "/auth" in self.path and self.status_code >= 400

    @property
    def is_admin(self) -> bool:
        return "/admin" in self.path

    @property
    def is_wallet_op(self) -> bool:
        return "/wallet" in self.path

    @property
    def is_transfer(self) -> bool:
        return "/transfer" in self.path

    @property
    def is_unknown_path(self) -> bool:
        return self.status_code == 404

    @property
    def is_signup(self) -> bool:
        """Successful or attempted POST to the wallet's sign-up endpoint."""
        return "/auth/sign-up" in self.path

    @property
    def is_signup_success(self) -> bool:
        return self.is_signup and self.status_code in (200, 201)


# ─────────────────────────────────────────────────────────────────────────────
# Two-layer session window
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SessionWindow:
    """
    Maintains two views of a session simultaneously:

    requests:          Rolling deque of last BEHAVIOR_WINDOW_SIZE requests.
                       Used for window-layer scoring.

    cumulative_scores: Lifetime accumulated evidence per category.
                       Decays by DECAY_RATE on each new request.

    attack_type:       Current committed classification.
    auth_fail_count:   Cumulative auth failures (used by credential_based_attacks strategy).
    """
    requests:          deque = field(default_factory=lambda: deque(maxlen=BEHAVIOR_WINDOW_SIZE))
    cumulative_scores: dict  = field(default_factory=lambda: {c: 0.0 for c in CATEGORIES})
    attack_type:       str   = "unknown_suspicious"
    auth_fail_count:   int   = 0

    def add(self, signal: RequestSignal) -> None:
        """Decay cumulative evidence, then add the new signal's contribution."""
        for cat in CATEGORIES:
            self.cumulative_scores[cat] *= DECAY_RATE

        delta = _score_signal(signal)
        for cat in CATEGORIES:
            self.cumulative_scores[cat] += delta.get(cat, 0.0)

        self.requests.append(signal)

        if signal.is_auth_error:
            self.auth_fail_count += 1

    def extract_window_features(self) -> dict:
        """Aggregate features from the rolling window for window-layer scoring."""
        reqs = list(self.requests)
        n = len(reqs)
        if n == 0:
            return {}

        errors        = sum(1 for r in reqs if r.is_error)
        admin_actions = sum(1 for r in reqs if r.is_admin)
        wallet_ops    = sum(1 for r in reqs if r.is_wallet_op)
        transfers     = sum(1 for r in reqs if r.is_transfer)
        signups       = sum(1 for r in reqs if r.is_signup)
        unique_ep     = len(set(r.path for r in reqs))
        think_times   = [r.think_time_ms for r in reqs if r.think_time_ms > 0]
        avg_think     = sum(think_times) / len(think_times) if think_times else 0

        if n >= 2:
            duration_sec = reqs[-1].timestamp - reqs[0].timestamp
            rpm = (n / duration_sec * 60) if duration_sec > 0 else 0
        else:
            rpm = 0

        return {
            "requests_per_minute": rpm,
            "error_ratio":         errors / n,
            "unique_endpoints":    unique_ep,
            "admin_action_count":  admin_actions,
            "wallet_action_ratio": wallet_ops / n,
            "transfer_count":      transfers,
            "signup_count":        signups,
            "signup_ratio":        signups / n,
            "avg_think_time_ms":   avg_think,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Per-request signal scoring (cumulative layer)
# ─────────────────────────────────────────────────────────────────────────────

def _score_signal(signal: RequestSignal) -> dict:
    """
    Score a single request signal against each attack category.
    Per-request increments accumulate across the session lifetime with decay.
    """
    delta = {c: 0.0 for c in CATEGORIES}

    # Credential-based attacks (failed logins, fast retries)
    if signal.is_auth_error:
        delta["credential_based_attacks"] += 1.0
    if signal.think_time_ms < 500 and signal.is_error:
        delta["credential_based_attacks"] += 0.5

    # Endpoint scanning (admin probing, 404s, broad surface coverage)
    if signal.is_admin:
        delta["endpoint_scanning"] += 1.0
    if signal.is_unknown_path:
        delta["endpoint_scanning"] += 0.8
    if signal.is_error and not signal.is_auth_error:
        delta["endpoint_scanning"] += 0.3

    # Financial fraud (wallet ops, transfers)
    if signal.is_wallet_op:
        delta["financial_fraud"] += 0.8
    if signal.is_transfer:
        delta["financial_fraud"] += 1.0

    # Account creation (POSTs to sign-up, especially with low think time)
    if signal.is_signup:
        delta["account_creation"] += 1.0
    if signal.is_signup_success and signal.think_time_ms < 800:
        delta["account_creation"] += 0.5

    return delta


# ─────────────────────────────────────────────────────────────────────────────
# Window-layer scoring
# ─────────────────────────────────────────────────────────────────────────────

def _score_window(features: dict) -> dict:
    """Score the rolling window features against each attack category."""
    scores = {c: 0.0 for c in CATEGORIES}

    rpm            = features.get("requests_per_minute", 0)
    error_ratio    = features.get("error_ratio", 0)
    unique_ep      = features.get("unique_endpoints", 0)
    admin_actions  = features.get("admin_action_count", 0)
    wallet_ratio   = features.get("wallet_action_ratio", 0)
    transfer_count = features.get("transfer_count", 0)
    signup_count   = features.get("signup_count", 0)
    signup_ratio   = features.get("signup_ratio", 0)
    avg_think_time = features.get("avg_think_time_ms", 0)

    # Credential-based attacks
    if rpm > 80 and avg_think_time < 500:   scores["credential_based_attacks"] += 2.0
    if error_ratio > 0.4:                   scores["credential_based_attacks"] += 2.0

    # Endpoint scanning
    if unique_ep > 8:                       scores["endpoint_scanning"] += 2.0
    if admin_actions > 2:                   scores["endpoint_scanning"] += 2.0
    if error_ratio > 0.1:                   scores["endpoint_scanning"] += 1.0

    # Financial fraud
    if wallet_ratio > 0.5:                  scores["financial_fraud"] += 2.0
    if wallet_ratio > 0.8:                  scores["financial_fraud"] += 1.0
    if transfer_count > 3:                  scores["financial_fraud"] += 2.0

    # Account creation (high ratio of sign-up calls in window)
    if signup_count >= 3:                   scores["account_creation"] += 2.0
    if signup_ratio > 0.5:                  scores["account_creation"] += 2.0

    return scores


# ─────────────────────────────────────────────────────────────────────────────
# Combined two-layer classifier
# ─────────────────────────────────────────────────────────────────────────────

def classify_behavior(window: SessionWindow) -> str:
    """
    Two-layer classification combining window and cumulative evidence.

    Combined score per category:
      combined = 0.6 × window_score + 0.4 × cumulative_score

    Confidence check:
      Winner must beat second place by CONFIDENCE_MARGIN.
      If not → unknown_suspicious (insufficient evidence).
    """
    cumulative = window.cumulative_scores

    if len(window.requests) >= BEHAVIOR_WINDOW_SIZE:
        features = window.extract_window_features()
        window_scores = _score_window(features)
    else:
        window_scores = {c: 0.0 for c in CATEGORIES}

    combined = {
        c: WINDOW_WEIGHT * window_scores[c] + CUMULATIVE_WEIGHT * cumulative[c]
        for c in CATEGORIES
    }

    sorted_scores = sorted(combined.values(), reverse=True)
    best          = max(combined, key=lambda k: combined[k])
    top_score     = sorted_scores[0]
    second_score  = sorted_scores[1]

    if top_score == 0:
        return "unknown_suspicious"

    if (top_score - second_score) < CONFIDENCE_MARGIN:
        return "unknown_suspicious"

    return best

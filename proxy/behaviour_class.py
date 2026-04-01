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

This mirrors the two-layer state model used by Suricata and commercial SIEMs:
  - Short-term window handles fast attacks and tactic shifts
  - Long-term cumulative handles slow multi-phase attacks like scanning
  - Neither layer alone is sufficient — both are needed

Decay rate = 0.85 per request, derived from baseline sessions:
  median=7 requests → signal from request 1 contributes 0.85^7 ≈ 32% at end
  p75=10 requests   → signal from request 1 contributes 0.85^10 ≈ 20% at end
  This keeps early signals relevant without dominating recent behavior.

Window size = 6, derived from p25 of total_requests in baseline_sessions.csv.
Confidence margin = 1, minimum score gap to commit a classification.
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
# 0.85 derived from baseline session length distribution:
#   at median session length (7 req), earliest signal = 0.85^7 ≈ 32% weight
#   at p75 session length (10 req),  earliest signal = 0.85^10 ≈ 20% weight
DECAY_RATE = 0.85

# Weighted combination of window and cumulative scores
WINDOW_WEIGHT     = 0.6
CUMULATIVE_WEIGHT = 0.4

# Minimum score gap between winner and second place.
# If gap < CONFIDENCE_MARGIN → unknown_suspicious.
# Prevents committing on ambiguous evidence.
CONFIDENCE_MARGIN = 1

# Attack categories
CATEGORIES = ["brute_force", "scanning", "fraud"]


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


# ─────────────────────────────────────────────────────────────────────────────
# Two-layer session window
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SessionWindow:
    """
    Maintains two views of a session simultaneously:

    requests:          Rolling deque of last BEHAVIOR_WINDOW_SIZE requests.
                       Used for window-layer scoring (recent behavior).

    cumulative_scores: Lifetime accumulated evidence per category.
                       Decays by DECAY_RATE on each new request so
                       old signals fade but never disappear entirely.

    attack_type:       Current committed classification.
    auth_fail_count:   Cumulative auth failures (used by brute_force strategy).
    """
    requests:          deque = field(default_factory=lambda: deque(maxlen=BEHAVIOR_WINDOW_SIZE))
    cumulative_scores: dict  = field(default_factory=lambda: {c: 0.0 for c in CATEGORIES})
    attack_type:       str   = "unknown_suspicious"
    auth_fail_count:   int   = 0

    def add(self, signal: RequestSignal) -> None:
        """
        Add a new request signal and update cumulative scores.
        Cumulative scores decay first, then new signal points are added.
        This means every existing evidence point loses 15% weight
        before the new request contributes its evidence.
        """
        # Decay existing cumulative evidence
        for cat in CATEGORIES:
            self.cumulative_scores[cat] *= DECAY_RATE

        # Add new signal to cumulative scores
        delta = _score_signal(signal)
        for cat in CATEGORIES:
            self.cumulative_scores[cat] += delta.get(cat, 0.0)

        # Add to rolling window
        self.requests.append(signal)

        # Track auth failures cumulatively for brute force strategy
        if signal.is_auth_error:
            self.auth_fail_count += 1

    def extract_window_features(self) -> dict:
        """
        Extract behavioral features from the rolling window.
        Used for window-layer scoring — captures recent behavior.
        """
        reqs = list(self.requests)
        n = len(reqs)
        if n == 0:
            return {}

        errors        = sum(1 for r in reqs if r.is_error)
        admin_actions = sum(1 for r in reqs if r.is_admin)
        wallet_ops    = sum(1 for r in reqs if r.is_wallet_op)
        transfers     = sum(1 for r in reqs if r.is_transfer)
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
            "avg_think_time_ms":   avg_think,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Per-request signal scoring (used for cumulative layer)
# ─────────────────────────────────────────────────────────────────────────────

def _score_signal(signal: RequestSignal) -> dict:
    """
    Score a single request signal against each attack category.
    Returns a dict of {category: points} for cumulative accumulation.

    These are per-request increments — they accumulate across the
    session lifetime with decay applied before each addition.
    """
    delta = {c: 0.0 for c in CATEGORIES}

    # Brute force signals
    if signal.is_auth_error:
        delta["brute_force"] += 1.0
    if signal.think_time_ms < 500 and signal.is_error:
        delta["brute_force"] += 0.5

    # Scanning signals
    if signal.is_admin:
        delta["scanning"] += 1.0
    if signal.is_unknown_path:
        delta["scanning"] += 0.8
    if signal.is_error and not signal.is_auth_error:
        delta["scanning"] += 0.3

    # Fraud signals
    if signal.is_wallet_op:
        delta["fraud"] += 0.8
    if signal.is_transfer:
        delta["fraud"] += 1.0

    return delta


# ─────────────────────────────────────────────────────────────────────────────
# Window-layer scoring (same logic as before, operates on feature dict)
# ─────────────────────────────────────────────────────────────────────────────

def _score_window(features: dict) -> dict:
    """
    Score the rolling window features against each attack category.
    Returns {category: score} for window-layer contribution.
    """
    scores = {c: 0.0 for c in CATEGORIES}

    rpm            = features.get("requests_per_minute", 0)
    error_ratio    = features.get("error_ratio", 0)
    unique_ep      = features.get("unique_endpoints", 0)
    admin_actions  = features.get("admin_action_count", 0)
    wallet_ratio   = features.get("wallet_action_ratio", 0)
    transfer_count = features.get("transfer_count", 0)
    avg_think_time = features.get("avg_think_time_ms", 0)

    # Brute force
    if rpm > 80 and avg_think_time < 500:   scores["brute_force"] += 2.0
    if error_ratio > 0.4:                   scores["brute_force"] += 2.0

    # Scanning
    if unique_ep > 8:                       scores["scanning"] += 2.0
    if admin_actions > 2:                   scores["scanning"] += 2.0
    if error_ratio > 0.1:                   scores["scanning"] += 1.0

    # Fraud
    if wallet_ratio > 0.5:                  scores["fraud"] += 2.0
    if wallet_ratio > 0.8:                  scores["fraud"] += 1.0
    if transfer_count > 3:                  scores["fraud"] += 2.0

    return scores


# ─────────────────────────────────────────────────────────────────────────────
# Combined two-layer classifier
# ─────────────────────────────────────────────────────────────────────────────

def classify_behavior(window: SessionWindow) -> str:
    """
    Two-layer classification combining window and cumulative evidence.

    Window layer (60% weight):
      Scores features from the last BEHAVIOR_WINDOW_SIZE requests.
      Only active when window is full — deferred until enough data.
      Captures what the attacker is doing right now.

    Cumulative layer (40% weight):
      Scores accumulated per-request signals across session lifetime.
      Active from the first request — provides early orientation.
      Captures what the attacker has done throughout the session.
      Decays over time so old evidence fades but doesn't vanish.

    Combined score per category:
      combined = 0.6 × window_score + 0.4 × cumulative_score

    Confidence check:
      Winner must beat second place by CONFIDENCE_MARGIN.
      If not → unknown_suspicious (insufficient evidence).
    """
    # ── Cumulative layer ──────────────────────────────────────────────────────
    cumulative = window.cumulative_scores

    # ── Window layer — only when full ────────────────────────────────────────
    if len(window.requests) >= BEHAVIOR_WINDOW_SIZE:
        features = window.extract_window_features()
        window_scores = _score_window(features)
    else:
        # Window not full yet — window layer contributes nothing
        window_scores = {c: 0.0 for c in CATEGORIES}

    # ── Combine ───────────────────────────────────────────────────────────────
    combined = {
        c: WINDOW_WEIGHT * window_scores[c] + CUMULATIVE_WEIGHT * cumulative[c]
        for c in CATEGORIES
    }

    # ── Confidence check ──────────────────────────────────────────────────────
    sorted_scores = sorted(combined.values(), reverse=True)
    best          = max(combined, key=lambda k: combined[k])
    top_score     = sorted_scores[0]
    second_score  = sorted_scores[1]

    if top_score == 0:
        return "unknown_suspicious"

    if (top_score - second_score) < CONFIDENCE_MARGIN:
        return "unknown_suspicious"

    return best
"""
GATE80 — Anomaly Detector
detection/model.py

Session-level behavioral anomaly detection.
Extracts 28 features from live HTTP request stream and scores each session
using a loaded Isolation Forest model.

Feature thresholds documented inline with citations.
"""

import math
import time
import pandas as pd
import joblib
import logging
import threading
from dataclasses import dataclass, field
from typing import Optional, Dict, Tuple
import numpy as np

logger = logging.getLogger(__name__)

MIN_REQUESTS_BEFORE_SCORING = 3
ANOMALY_SCORE_THRESHOLD = -0.013

FEATURE_NAMES = [
    # ── Session volume ────────────────────────────────────────────────────────
    "total_requests",
    "session_duration_sec",
    "requests_per_minute",
    "requests_per_second",

    # ── Error signals — split by type ─────────────────────────────────────────
    # error_ratio: general errors / total requests
    # http_4xx_ratio: 4xx / total — scanning/probing signal
    #   Source: Balla et al. ICT 2011, p. 429 (normal ~4%, scanner >20%)
    #   DOI: 10.1109/CTS.2011.5898963
    # http_5xx_ratio: 5xx / total — attack-induced server stress
    #   Source: Goseva-Popstojanova et al. Computers & Security 2014,
    #   Table 13, WebDBAdmin dataset — feature #24 ranked #1 by info gain
    #   DOI: 10.1016/j.cose.2014.01.006
    "error_ratio",
    "error_count",
    "http_4xx_ratio",
    "http_5xx_ratio",

    # ── Login-specific signals ────────────────────────────────────────────────
    # failed_login_count: raw failed auth attempt count
    #   Source: NIST SP 800-63B §5.2.3
    #           Alsaleh et al. TDSC 2012, p. 128 DOI: 10.1109/TDSC.2011.24
    # login_attempts: total login attempts in session
    #   Source: Zin Htet et al. ICAIT 2025, p. 3
    #   DOI: 10.1109/ICAIT68809.2025.11236796
    # failed_login_ratio: failed / total login attempts
    #   Normal human: < 0.5   Attack: > 0.80
    #   Source: NIST SP 800-63B §5.2.3
    "failed_login_count",
    "login_attempts",
    "failed_login_ratio",

    # ── Endpoint behavior ─────────────────────────────────────────────────────
    # unique_endpoints, endpoint_entropy: sequence diversity
    #   Source: Oikonomou & Mirkovic ICC 2009, p. 4
    #   DOI: 10.1109/ICC.2009.5199191
    #   Sequence probability < 0.05 = bot (98.06% of bots below threshold)
    # admin_action_count: raw count of admin endpoint hits
    #   Source: OWASP ATH v1.3 OAT-014
    # admin_ratio: admin hits / total requests
    #   Source: OWASP ATH v1.3 OAT-014
    # has_admin_access: boolean — any admin endpoint reached successfully
    #   Source: OWASP ATH v1.3 OAT-014
    "unique_endpoints",
    "endpoint_entropy",
    "admin_action_count",
    "admin_ratio",
    "has_admin_access",

    # ── Wallet / financial signals ────────────────────────────────────────────
    # wallet_action_ratio: [CALIBRATED] — no published numerical threshold
    #   Directional: OWASP ATH v1.3 OAT-012
    #   See docs/references.md §gaps
    # financial_error_count: errors specifically on wallet endpoints
    "wallet_action_ratio",
    "transfer_count",
    "topup_count",
    "withdraw_count",
    "pay_bill_count",
    "financial_error_count",

    # ── Timing signals ────────────────────────────────────────────────────────
    # avg_think_time_ms: mean inter-request interval
    #   Bot: 17–100 ms   Human searching: 6,300 ms   Human relaxed: 60,100 ms
    #   Source: Oikonomou & Mirkovic ICC 2009, Fig. 1
    #   DOI: 10.1109/ICC.2009.5199191
    # min_think_time_ms: minimum inter-request interval
    #   Any value < 100 ms = strong bot signal (Oikonomou 2009)
    # think_time_cv: coefficient of variation (std / mean)
    #   Bot: < 0.3 (near-periodic)   Human: > 1.5 (dispersed, power-law)
    #   Source: Derived from Oikonomou & Mirkovic ICC 2009
    "avg_think_time_ms",
    "std_think_time_ms",
    "min_think_time_ms",
    "max_think_time_ms",
    "think_time_cv",

    # ── Response time ─────────────────────────────────────────────────────────
    "avg_response_time_ms",
]


@dataclass
class SessionState:
    session_id: str
    created_at: float = field(default_factory=time.time)
    last_request_at: float = field(default_factory=time.time)

    # Volume
    total_requests: int = 0

    # Error signals
    error_count: int = 0
    count_4xx: int = 0
    count_5xx: int = 0

    # Login signals
    failed_login_count: int = 0
    login_attempts: int = 0

    # Endpoint behavior
    endpoint_counts: dict = field(default_factory=dict)
    admin_action_count: int = 0
    admin_success_count: int = 0

    # Wallet / financial
    wallet_request_count: int = 0
    transfer_count: int = 0
    topup_count: int = 0
    withdraw_count: int = 0
    pay_bill_count: int = 0
    financial_error_count: int = 0

    # Timing
    think_times_ms: list = field(default_factory=list)
    response_times_ms: list = field(default_factory=list)

    # State
    is_anomalous: bool = False
    anomaly_score: float = 0.0
    flagged_at: Optional[float] = None


class AnomalyDetector:
    def __init__(self, model_path: str, scaler_path: str):
        self._lock = threading.Lock()
        self._sessions: Dict[str, SessionState] = {}

        logger.info("GATE80 ▶ loading model  : %s", model_path)
        self.model = joblib.load(model_path)
        logger.info("GATE80 ▶ loading scaler : %s", scaler_path)
        self.scaler = joblib.load(scaler_path)

        logger.info(
            "GATE80 ✅ detector ready — %d estimators, contamination=%.2f",
            self.model.n_estimators,
            self.model.contamination,
        )
        logger.info(
            "GATE80 ✅ thresholds — min_requests=%d, score_threshold=%.3f",
            MIN_REQUESTS_BEFORE_SCORING,
            ANOMALY_SCORE_THRESHOLD,
        )

    def get_or_create_session(self, session_id: str) -> SessionState:
        with self._lock:
            if session_id not in self._sessions:
                self._sessions[session_id] = SessionState(session_id=session_id)
            return self._sessions[session_id]

    def remove_session(self, session_id: str) -> None:
        with self._lock:
            self._sessions.pop(session_id, None)

    @property
    def active_session_count(self) -> int:
        with self._lock:
            return len(self._sessions)

    def update_session(
        self,
        session_id: str,
        path: str,
        response_status: int,
        response_time_ms: int,
    ) -> None:
        with self._lock:
            s = self._sessions.get(session_id)
            if s is None:
                s = SessionState(session_id=session_id)
                self._sessions[session_id] = s

            now = time.time()
            if s.total_requests > 0:
                think_ms = (now - s.last_request_at) * 1000.0
                s.think_times_ms.append(think_ms)
            s.last_request_at = now
            s.total_requests += 1

            # Error classification — split 4xx and 5xx
            if response_status >= 400:
                s.error_count += 1
            if 400 <= response_status < 500:
                s.count_4xx += 1
            if response_status >= 500:
                s.count_5xx += 1

            s.response_times_ms.append(float(response_time_ms))

            # Endpoint tracking
            clean_path = _normalise_path(path)
            s.endpoint_counts[clean_path] = (
                s.endpoint_counts.get(clean_path, 0) + 1
            )

            # Login signals
            if _is_login(path):
                s.login_attempts += 1
                if response_status >= 400:
                    s.failed_login_count += 1

            # Admin signals
            if _is_admin(path):
                s.admin_action_count += 1
                if response_status < 400:
                    s.admin_success_count += 1

            # Wallet signals
            if _is_wallet(path):
                s.wallet_request_count += 1
                if response_status >= 400:
                    s.financial_error_count += 1
            if _is_transfer(path): s.transfer_count += 1
            if _is_topup(path):    s.topup_count += 1
            if _is_withdraw(path): s.withdraw_count += 1
            if _is_pay_bill(path): s.pay_bill_count += 1

    def score_session(self, session_id: str) -> Tuple[bool, float]:
        with self._lock:
            s = self._sessions.get(session_id)
            if s is None:
                return False, 0.0
            if s.is_anomalous:
                return True, s.anomaly_score
            if s.total_requests < MIN_REQUESTS_BEFORE_SCORING:
                return False, 0.0

            vec = _build_feature_vector(s)
            x = pd.DataFrame([vec], columns=FEATURE_NAMES)
            x_scaled = self.scaler.transform(x)
            raw_score = float(self.model.decision_function(x_scaled)[0])
            is_anomalous = raw_score < ANOMALY_SCORE_THRESHOLD

        with self._lock:
            s = self._sessions.get(session_id)
            if s:
                s.anomaly_score = raw_score
                if is_anomalous and not s.is_anomalous:
                    s.is_anomalous = True
                    s.flagged_at = time.time()
                    logger.warning(
                        "GATE80 🚨 anomalous session flagged: %s  "
                        "(score=%.4f, threshold=%.3f)",
                        session_id, raw_score, ANOMALY_SCORE_THRESHOLD,
                    )

        return is_anomalous, raw_score

    def process_request(
        self,
        session_id: str,
        path: str,
        response_status: int,
        response_time_ms: int,
    ) -> Tuple[bool, float]:
        self.update_session(session_id, path, response_status, response_time_ms)
        return self.score_session(session_id)


# ─────────────────────────────────────────────────────────────────────────────
# Path helpers
# ─────────────────────────────────────────────────────────────────────────────

def _normalise_path(path: str) -> str:
    import re
    path = re.sub(r"/[a-zA-Z]{1,4}_\d{4,}", "/{id}", path)
    path = re.sub(r"/\d+", "/{id}", path)
    return path.rstrip("/") or "/"


def _is_login(path: str) -> bool:
    return "sign-in" in path or "sign-up" in path

def _is_admin(path: str) -> bool:
    return "/admin" in path

def _is_wallet(path: str) -> bool:
    return "/wallet" in path

def _is_transfer(path: str) -> bool:
    return "transfer" in path

def _is_topup(path: str) -> bool:
    return "topup" in path

def _is_withdraw(path: str) -> bool:
    return "withdraw" in path

def _is_pay_bill(path: str) -> bool:
    return "pay-bill" in path


# ─────────────────────────────────────────────────────────────────────────────
# Shannon entropy
# ─────────────────────────────────────────────────────────────────────────────

def _shannon_entropy(counts: dict) -> float:
    total = sum(counts.values())
    if total == 0:
        return 0.0
    return -sum(
        (n / total) * math.log2(n / total)
        for n in counts.values() if n > 0
    )


# ─────────────────────────────────────────────────────────────────────────────
# Feature vector builder — must match FEATURE_NAMES order exactly
# ─────────────────────────────────────────────────────────────────────────────

def _build_feature_vector(s: SessionState) -> list:
    now          = time.time()
    duration_sec = max(now - s.created_at, 1e-6)
    think_times  = s.think_times_ms
    resp_times   = s.response_times_ms
    n            = max(s.total_requests, 1)

    avg_think = float(np.mean(think_times)) if think_times else 0.0
    std_think = float(np.std(think_times))  if len(think_times) > 1 else 0.0
    min_think = float(np.min(think_times))  if think_times else 0.0
    max_think = float(np.max(think_times))  if think_times else 0.0
    cv_think  = (std_think / avg_think)     if avg_think > 0 else 0.0

    login_attempts = max(s.login_attempts, 1)

    return [
        # Session volume
        s.total_requests,
        duration_sec,
        (s.total_requests / duration_sec) * 60.0,
        s.total_requests / duration_sec,

        # Error signals
        s.error_count / n,
        float(s.error_count),
        s.count_4xx / n,
        s.count_5xx / n,

        # Login signals
        float(s.failed_login_count),
        float(s.login_attempts),
        s.failed_login_count / login_attempts,

        # Endpoint behavior
        len(s.endpoint_counts),
        _shannon_entropy(s.endpoint_counts),
        s.admin_action_count,
        s.admin_action_count / n,
        float(s.admin_success_count > 0),

        # Wallet / financial
        s.wallet_request_count / n,
        s.transfer_count,
        s.topup_count,
        s.withdraw_count,
        s.pay_bill_count,
        float(s.financial_error_count),

        # Timing
        avg_think,
        std_think,
        min_think,
        max_think,
        cv_think,

        # Response time
        float(np.mean(resp_times)) if resp_times else 0.0,
    ]
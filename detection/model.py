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
    "total_requests",
    "session_duration_sec",
    "requests_per_minute",
    "requests_per_second",
    "error_ratio",
    "error_count",
    "unique_endpoints",
    "endpoint_entropy",
    "admin_action_count",
    "wallet_action_ratio",
    "transfer_count",
    "topup_count",
    "withdraw_count",
    "pay_bill_count",
    "avg_think_time_ms",
    "std_think_time_ms",
    "avg_response_time_ms",
]


@dataclass
class SessionState:
    session_id: str
    created_at: float = field(default_factory=time.time)
    last_request_at: float = field(default_factory=time.time)
    total_requests: int = 0
    error_count: int = 0
    endpoint_counts: dict = field(default_factory=dict)
    admin_action_count: int = 0
    wallet_request_count: int = 0
    transfer_count: int = 0
    topup_count: int = 0
    withdraw_count: int = 0
    pay_bill_count: int = 0
    think_times_ms: list = field(default_factory=list)
    response_times_ms: list = field(default_factory=list)
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
                logger.debug("New session tracked: %s", session_id)
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

            if response_status >= 400:
                s.error_count += 1

            s.response_times_ms.append(float(response_time_ms))

            clean_path = _normalise_path(path)
            s.endpoint_counts[clean_path] = s.endpoint_counts.get(clean_path, 0) + 1

            if _is_admin(path):    s.admin_action_count += 1
            if _is_wallet(path):   s.wallet_request_count += 1
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
                logger.debug(
                    "GATE80 ⏳ session %s has %d requests — waiting for %d",
                    session_id, s.total_requests, MIN_REQUESTS_BEFORE_SCORING,
                )
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
                        "GATE80 🚨 anomalous session flagged: %s  (score=%.4f, threshold=%.3f)",
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


def _normalise_path(path: str) -> str:
    import re
    path = re.sub(r"/[a-zA-Z]{1,4}_\d{4,}", "/{id}", path)
    path = re.sub(r"/\d+", "/{id}", path)
    return path.rstrip("/") or "/"


def _is_admin(path: str) -> bool:    return "/admin" in path
def _is_wallet(path: str) -> bool:   return "/wallet" in path
def _is_transfer(path: str) -> bool: return "transfer" in path
def _is_topup(path: str) -> bool:    return "topup" in path
def _is_withdraw(path: str) -> bool: return "withdraw" in path
def _is_pay_bill(path: str) -> bool: return "pay-bill" in path


def _shannon_entropy(counts: dict) -> float:
    total = sum(counts.values())
    if total == 0:
        return 0.0
    entropy = 0.0
    for n in counts.values():
        if n > 0:
            p = n / total
            entropy -= p * math.log2(p)
    return entropy


def _build_feature_vector(s: SessionState) -> list:
    now          = time.time()
    duration_sec = max(now - s.created_at, 1e-6)
    think_times  = s.think_times_ms
    resp_times   = s.response_times_ms

    return [
        s.total_requests,
        duration_sec,
        (s.total_requests / duration_sec) * 60.0,      # requests_per_minute
        s.total_requests / duration_sec,                # requests_per_second
        s.error_count / max(s.total_requests, 1),       # error_ratio
        float(s.error_count),                           # error_count
        len(s.endpoint_counts),
        _shannon_entropy(s.endpoint_counts),
        s.admin_action_count,
        s.wallet_request_count / max(s.total_requests, 1),
        s.transfer_count,
        s.topup_count,
        s.withdraw_count,
        s.pay_bill_count,
        float(np.mean(think_times))   if think_times          else 0.0,
        float(np.std(think_times))    if len(think_times) > 1 else 0.0,
        float(np.mean(resp_times))    if resp_times           else 0.0,
    ]
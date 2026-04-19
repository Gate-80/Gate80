"""
GATE80 — Decoy API
db/log_models.py

Decoy-side logs stored in proxy_logs.db (shared with ProxyRequest).
"""

from sqlalchemy import Column, String, Integer, Text, DateTime, Float
from sqlalchemy.sql import func
from proxy.db.database import Base


class DecoyRequest(Base):
    __tablename__ = "decoy_requests"

    id         = Column(Integer, primary_key=True, autoincrement=True)
    request_id = Column(String(50), unique=True, index=True, nullable=False)

    # When and who
    timestamp  = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    client_ip  = Column(String(50), index=True)
    session_id = Column(String(200), index=True, nullable=True)

    # Request
    method       = Column(String(10), nullable=False)
    path         = Column(String(500), nullable=False, index=True)
    query_params = Column(Text)
    headers      = Column(Text)
    body         = Column(Text)

    # Response sent back to attacker
    response_status  = Column(Integer)
    response_body    = Column(Text)
    response_time_ms = Column(Integer)

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    def __repr__(self):
        return f"<DecoyRequest {self.request_id} {self.method} {self.path} \u2192 {self.response_status}>"


class DeceptionPlanLog(Base):
    __tablename__ = "deception_plan_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    request_id = Column(String(50), index=True, nullable=False)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)

    session_id = Column(String(200), index=True, nullable=False)
    attack_type = Column(String(50), index=True, nullable=False)
    method = Column(String(10), nullable=False, index=True)
    path = Column(String(500), nullable=False, index=True)

    plan_id = Column(String(50), index=True, nullable=False)
    plan_source = Column(String(20), nullable=False, index=True)
    model_name = Column(String(100), nullable=True)
    prompt_version = Column(String(50), nullable=True)
    confidence = Column(Float, nullable=True)
    rationale = Column(Text)
    generation_error = Column(Text)

    response_status_before = Column(Integer, index=True)
    response_status_after = Column(Integer, index=True)

    raw_plan = Column(Text)
    validated_plan = Column(Text)
    applied_actions = Column(Text)
    rejected_actions = Column(Text)
    final_body_preview = Column(Text)

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    def __repr__(self):
        return (
            f"<DeceptionPlanLog {self.request_id} {self.attack_type} "
            f"{self.plan_source} {self.response_status_before}->{self.response_status_after}>"
        )

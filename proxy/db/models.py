import json
from typing import Optional
from sqlalchemy import Column, String, Integer, Float, Boolean, Text, DateTime
from sqlalchemy.sql import func
from proxy.db.database import Base


class ProxyRequest(Base):
    __tablename__ = "proxy_requests"

    id           = Column(Integer, primary_key=True, index=True, autoincrement=True)
    request_id   = Column(String(50), unique=True, index=True, nullable=False)

    # Request details
    timestamp    = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    client_ip    = Column(String(50),  index=True)
    method       = Column(String(10),  nullable=False, index=True)
    path         = Column(String(500), nullable=False, index=True)
    query_params = Column(Text)
    headers      = Column(Text)
    body         = Column(Text)

    # Response details
    response_status  = Column(Integer, index=True)
    response_time_ms = Column(Integer)

    # Routing (original)
    forwarded_to_backend = Column(Boolean, default=True)
    backend_error        = Column(String(200))

    # Week 6 — detection & adaptive routing
    session_id    = Column(String(200), index=True, nullable=True)
    anomaly_score = Column(Float, nullable=True)
    routed_to     = Column(String(20),  default="backend", nullable=False, index=True)

    # Legacy detection flags
    flagged_as_suspicious = Column(Boolean, default=False, index=True)
    suspicion_reason      = Column(String(200))

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    def __repr__(self) -> str:
        return (
            f"<ProxyRequest {self.request_id} {self.method} {self.path} "
            f"-> {self.response_status} [{self.routed_to}]>"
        )

    @staticmethod
    def dict_to_json(data) -> Optional[str]:
        if data is None:
            return None
        try:
            return json.dumps(dict(data))
        except (TypeError, ValueError):
            return str(data)

    @staticmethod
    def json_to_dict(json_str) -> dict:
        if json_str is None:
            return {}
        try:
            return json.loads(json_str)
        except (TypeError, ValueError):
            return {}
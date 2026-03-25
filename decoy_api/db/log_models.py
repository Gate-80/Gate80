"""
GATE80 — Decoy API
db/log_models.py

DecoyRequest model — logs every attacker interaction.
stored in proxy_logs.db (shared with ProxyRequest)
"""

from sqlalchemy import Column, String, Integer, Text, DateTime
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
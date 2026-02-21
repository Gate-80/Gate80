
from sqlalchemy import Column, String, Integer, Float, Boolean, Text, DateTime
from sqlalchemy.sql import func
from proxy.db.database import Base
import json


class ProxyRequest(Base):
    """Model for logging all proxy requests"""
    __tablename__ = "proxy_requests"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    request_id = Column(String(50), unique=True, index=True, nullable=False)
    
    # Request details
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    client_ip = Column(String(50), index=True)
    method = Column(String(10), nullable=False, index=True)  # GET, POST, etc.
    path = Column(String(500), nullable=False, index=True)
    query_params = Column(Text)  # JSON string
    headers = Column(Text)  # JSON string
    body = Column(Text)  # JSON string (for POST/PUT/PATCH)
    
    # Response details
    response_status = Column(Integer, index=True)
    response_time_ms = Column(Integer)
    
    # Proxy routing
    forwarded_to_backend = Column(Boolean, default=True)
    backend_error = Column(String(200))  # Error message if backend unreachable
    
    # Detection flags (for future use)
    flagged_as_suspicious = Column(Boolean, default=False, index=True)
    suspicion_reason = Column(String(200))
    
    # Metadata
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    def __repr__(self):
        return f"<ProxyRequest {self.request_id} {self.method} {self.path} -> {self.response_status}>"
    
    @staticmethod
    def dict_to_json(data):
        """Convert dict to JSON string, handle non-serializable types"""
        if data is None:
            return None
        try:
            return json.dumps(dict(data))
        except (TypeError, ValueError):
            return str(data)
    
    @staticmethod
    def json_to_dict(json_str):
        """Convert JSON string back to dict"""
        if json_str is None:
            return None
        try:
            return json.loads(json_str)
        except (TypeError, ValueError):
            return {}
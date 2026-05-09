"""
Platform models.

These four tables describe customer onboarding state and decoy configuration.
They live in gate80_platform.db, separate from any customer's wallet data.

Note on cross-DB references:
    - Project.user_id refers to a User row in the customer's wallet DB.
    - DecoyConfig.created_by_user_id refers to the same.
    SQLite cannot enforce foreign keys across DB files, so these are kept
    as plain string columns. App code is responsible for ownership checks.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, JSON, String
from sqlalchemy.orm import relationship

from gate80_platform.db.database import Base


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


class Project(Base):
    """A customer's onboarded API project (one customer = one project)."""

    __tablename__ = "projects"

    id = Column(String, primary_key=True, index=True)

    # Owner reference into the customer wallet DB (not FK-enforced; cross-DB).
    user_id = Column(String, nullable=True, index=True)

    name = Column(String, nullable=False)
    customer_name = Column(String, nullable=False)
    environment = Column(String, default="Development")

    # How the OpenAPI spec arrived: file upload, URL fetch, or website crawl.
    source_type = Column(String, nullable=False)
    source_value = Column(String, nullable=False)

    onboarding_status = Column(String, default="imported")
    decoy_generation_status = Column(String, default="not_started")

    created_at = Column(DateTime(timezone=True), default=now_utc)
    updated_at = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)

    endpoints = relationship(
        "EndpointInventory",
        back_populates="project",
        cascade="all, delete-orphan",
    )
    decoy_configs = relationship(
        "DecoyConfig",
        back_populates="project",
        cascade="all, delete-orphan",
    )
    proxy_configs = relationship(
        "ProxyConfig",
        back_populates="project",
        cascade="all, delete-orphan",
    )


class EndpointInventory(Base):
    """One row per (project, path, method) parsed from the customer's OpenAPI spec.

    Holds the request/response JSON Schemas — used by the LLM planner in Phase 8
    to generate schema-conformant decoy responses.
    """

    __tablename__ = "endpoint_inventory"

    id = Column(String, primary_key=True, index=True)
    project_id = Column(String, ForeignKey("projects.id"), nullable=False)

    path = Column(String, nullable=False)
    method = Column(String, nullable=False)
    summary = Column(String)
    tag = Column(String)
    requires_auth = Column(Boolean, default=False)

    request_schema_json = Column(JSON)
    response_schema_json = Column(JSON)

    risk_score = Column(String, default="0")
    risk_level = Column(String, default="low")

    is_selected_for_decoy = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=now_utc)

    project = relationship("Project", back_populates="endpoints")
    decoy_configs = relationship(
        "DecoyConfig",
        back_populates="endpoint",
        cascade="all, delete-orphan",
    )


class DecoyConfig(Base):
    """Per-endpoint decoy response configuration (auto-generated or manually edited)."""

    __tablename__ = "decoy_config"

    id = Column(String, primary_key=True, index=True)
    project_id = Column(String, ForeignKey("projects.id"), nullable=False)
    endpoint_id = Column(String, ForeignKey("endpoint_inventory.id"), nullable=False)

    # Author reference into the customer wallet DB (not FK-enforced).
    created_by_user_id = Column(String, nullable=True, index=True)

    name = Column(String)
    description = Column(String)

    # decoy_type: fake_success | fake_failure | delayed_response | honey_data
    decoy_type = Column(String, nullable=False)
    status_code = Column(String, default="200")
    response_template = Column(JSON)
    headers_template = Column(JSON)
    trigger_condition = Column(JSON)
    delay_ms = Column(String, default="0")
    generation_source = Column(String, default="auto")
    review_status = Column(String, default="draft")
    is_enabled = Column(Boolean, default=True)

    created_at = Column(DateTime(timezone=True), default=now_utc)
    updated_at = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)

    project = relationship("Project", back_populates="decoy_configs")
    endpoint = relationship("EndpointInventory", back_populates="decoy_configs")


class ProxyConfig(Base):
    """Per-project proxy listener config (port, backend URL, enable flag).

    Phase 4 reads these rows at startup to spawn one proxy listener per active project.
    Medium scope: only one row exists (the demo project).
    """

    __tablename__ = "proxy_config"

    id = Column(String, primary_key=True, index=True)
    project_id = Column(String, ForeignKey("projects.id"), nullable=False, index=True)

    backend_base_url = Column(String, nullable=False)
    proxy_host = Column(String, default="127.0.0.1")
    listen_port = Column(String, default="8080")
    api_key = Column(String)
    mode = Column(String, default="reverse_proxy")
    is_active = Column(Boolean, default=True)

    created_at = Column(DateTime(timezone=True), default=now_utc)
    updated_at = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)

    project = relationship("Project", back_populates="proxy_configs")

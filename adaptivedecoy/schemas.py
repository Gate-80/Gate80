from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


AttackType = Literal[
    "credential_based_attacks",
    "endpoint_scanning",
    "financial_fraud",
    "account_creation",
]

StrategyType = Literal[
    "auth_honey_flow",
    "fake_endpoint_surface",
    "fake_business_flow",
    "sinkhole_signup_flow",
]

DecoyDepth = Literal["low", "medium", "high"]


class Signals(BaseModel):
    request_rate: float = Field(ge=0.0)
    endpoint_entropy: float = Field(ge=0.0)
    unique_endpoints: int = Field(ge=0)
    failed_auth_ratio: float = Field(ge=0.0, le=1.0)
    status_404_ratio: float = Field(ge=0.0, le=1.0)
    method_diversity: float = Field(ge=0.0, le=1.0)


class TargetContext(BaseModel):
    business_flow_targeted: bool = False
    authenticated: bool = False


class SessionSummary(BaseModel):
    session_id: str = Field(min_length=1)
    candidate_attack_type: AttackType
    signals: Signals
    target_context: TargetContext = Field(default_factory=TargetContext)


class DecoyPlan(BaseModel):
    attack_type: AttackType
    confidence: float = Field(ge=0.0, le=1.0)
    strategy: StrategyType
    decoy_depth: DecoyDepth
    ttl_seconds: int = Field(ge=60, le=600)
    reason: str = Field(min_length=1, max_length=240)
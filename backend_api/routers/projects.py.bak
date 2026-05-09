from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
import re
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend_api.db.database import get_db
from backend_api.db.models import DecoyConfig, EndpointInventory, Project, ProxyConfig, User
from backend_api.routers import onboarding as onboarding_routes
from backend_api.routers.onboarding import (
    DecoyConfigCreate,
    DecoyGenerateRequest,
    DecoyUpdateRequest,
    EndpointSelectRequest,
    ProjectCreate,
    ProxyConfigCreate,
    generated_proxy_config,
)
from backend_api.routers.user_authentication import require_user
from decoy_api.db.log_models import DecoyRequest, DeceptionPlanLog
from proxy.db.database import SessionLocal as ProxySessionLocal
from proxy.db.models import ProxyRequest


router = APIRouter(prefix="/projects", tags=["projects"])

KNOWN_GEO_BY_IP = {
    "8.8.8.8": {
        "country": "United States",
        "city": "Mountain View",
        "lat": 37.3861,
        "lon": -122.0839,
    },
    "9.9.9.9": {
        "country": "Switzerland",
        "city": "Zurich",
        "lat": 47.3769,
        "lon": 8.5417,
    },
    "1.1.1.1": {
        "country": "Australia",
        "city": "Brisbane",
        "lat": -27.4698,
        "lon": 153.0251,
    },
    "185.228.168.9": {
        "country": "United Kingdom",
        "city": "London",
        "lat": 51.5072,
        "lon": -0.1276,
    },
}


class ProjectUpdateRequest(BaseModel):
    name: Optional[str] = None
    environment: Optional[str] = None
    onboarding_status: Optional[str] = None


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _resolve_time_window(range_name: str) -> datetime | None:
    value = (range_name or "all").strip().lower()
    now = datetime.utcnow()

    if value == "24h":
        return now - timedelta(hours=24)
    if value == "7d":
        return now - timedelta(days=7)
    if value == "30d":
        return now - timedelta(days=30)
    return None


def _compile_project_path_patterns(project: Project, db: Session) -> list[re.Pattern[str]]:
    endpoints = (
        db.query(EndpointInventory)
        .filter(EndpointInventory.project_id == project.id)
        .all()
    )
    patterns: list[re.Pattern[str]] = []
    seen: set[str] = set()

    for endpoint in endpoints:
        template = (endpoint.path or "").strip()
        if not template or template in seen:
            continue
        seen.add(template)
        regex = re.sub(r"\{[^/]+\}", r"[^/]+", template.rstrip("/"))
        patterns.append(re.compile(rf"^{regex}/?$"))

    return patterns


def _path_matches_project(path: Optional[str], patterns: list[re.Pattern[str]]) -> bool:
    normalized = (path or "").strip().rstrip("/") or "/"
    return any(pattern.match(normalized) for pattern in patterns)


def _severity_from_attack(attack_type: Optional[str], routed_to: Optional[str], status_code: Optional[int]) -> str:
    attack = (attack_type or "").lower()
    route = (routed_to or "").lower()
    code = status_code or 0

    if attack == "fraud" or route == "decoy" or code >= 500:
        return "critical"
    if attack in {"brute_force", "scanning"} or code in {401, 403, 429}:
        return "high"
    if attack == "unknown_suspicious" or 400 <= code < 500:
        return "medium"
    return "low"


def _action_from_route(routed_to: Optional[str], flagged: bool) -> str:
    route = (routed_to or "").lower()
    if route == "decoy":
        return "blocked"
    if flagged:
        return "detected"
    if route == "error":
        return "error"
    return "allowed"


def _serialize_proxy_request(row: ProxyRequest) -> dict:
    severity = _severity_from_attack(row.attack_type, row.routed_to, row.response_status)
    action = _action_from_route(row.routed_to, bool(row.flagged_as_suspicious))
    return {
        "id": f"proxy-{row.id}",
        "kind": "proxy_request",
        "request_id": row.request_id,
        "timestamp": row.timestamp.isoformat() if row.timestamp else None,
        "client_ip": row.client_ip or "unknown",
        "source_ip": row.client_ip or "unknown",
        "method": row.method,
        "path": row.path,
        "status_code": row.response_status,
        "response_status": row.response_status,
        "response_time_ms": row.response_time_ms,
        "routed_to": row.routed_to or "backend",
        "flagged_as_suspicious": bool(row.flagged_as_suspicious),
        "attack_type": row.attack_type or "normal",
        "severity": severity,
        "action": action,
        "suspicion_reason": row.suspicion_reason,
    }


def _serialize_decoy_request(row: DecoyRequest) -> dict:
    return {
        "id": f"decoy-{row.id}",
        "kind": "decoy_request",
        "request_id": row.request_id,
        "timestamp": row.timestamp.isoformat() if row.timestamp else None,
        "client_ip": row.client_ip or "unknown",
        "source_ip": row.client_ip or "unknown",
        "method": row.method,
        "path": row.path,
        "status_code": row.response_status,
        "response_status": row.response_status,
        "response_time_ms": row.response_time_ms,
        "routed_to": "decoy",
        "flagged_as_suspicious": True,
        "attack_type": "deception_engaged",
        "severity": "critical",
        "action": "blocked",
        "suspicion_reason": "Request was routed to decoy",
    }


def _serialize_plan_log(row: DeceptionPlanLog) -> dict:
    severity = _severity_from_attack(row.attack_type, "decoy", row.response_status_after)
    return {
        "id": f"plan-{row.id}",
        "kind": "deception_plan",
        "request_id": row.request_id,
        "timestamp": row.timestamp.isoformat() if row.timestamp else None,
        "session_id": row.session_id,
        "method": row.method,
        "path": row.path,
        "attack_type": row.attack_type,
        "plan_source": row.plan_source,
        "model_name": row.model_name,
        "status_code": row.response_status_after,
        "severity": severity,
        "action": "blocked",
        "rationale": row.rationale,
    }


def _collect_project_traffic(project: Project, db: Session, limit: int) -> dict:
    patterns = _compile_project_path_patterns(project, db)
    if not patterns:
        return {
            "traffic_logs": [],
            "attack_origins": [],
            "most_attacked_apis": [],
            "security_events": [],
            "summary": {
                "total_requests": 0,
                "total_logs": 0,
                "suspicious_requests": 0,
                "blocked_requests": 0,
                "unique_source_ips": 0,
                "last_updated": _utc_now_iso(),
            },
        }

    proxy_db = ProxySessionLocal()
    try:
        proxy_rows = (
            proxy_db.query(ProxyRequest)
            .order_by(ProxyRequest.id.desc())
            .limit(max(limit * 8, 500))
            .all()
        )
        decoy_rows = (
            proxy_db.query(DecoyRequest)
            .order_by(DecoyRequest.id.desc())
            .limit(max(limit * 4, 250))
            .all()
        )
        plan_rows = (
            proxy_db.query(DeceptionPlanLog)
            .order_by(DeceptionPlanLog.id.desc())
            .limit(max(limit * 4, 250))
            .all()
        )
    finally:
        proxy_db.close()

    matched_proxy = [row for row in proxy_rows if _path_matches_project(row.path, patterns)]
    matched_decoy = [row for row in decoy_rows if _path_matches_project(row.path, patterns)]
    matched_plans = [row for row in plan_rows if _path_matches_project(row.path, patterns)]

    traffic_logs = sorted(
        [_serialize_proxy_request(row) for row in matched_proxy]
        + [_serialize_decoy_request(row) for row in matched_decoy],
        key=lambda item: (item["timestamp"] or "", item["id"]),
        reverse=True,
    )[:limit]

    origin_counts: dict[str, dict] = {}
    for item in traffic_logs:
        source_ip = item["source_ip"]
        origin = origin_counts.setdefault(
            source_ip,
            {
                "source_ip": source_ip,
                "client_ip": source_ip,
                "attempts": 0,
                "suspicious": 0,
                "location": "Unknown",
                "country": None,
                "city": None,
                "lat": None,
                "lon": None,
            },
        )
        origin["attempts"] += 1
        if item["severity"] in {"critical", "high", "medium"}:
            origin["suspicious"] += 1
        geo = KNOWN_GEO_BY_IP.get(source_ip)
        if geo:
            origin["country"] = geo["country"]
            origin["city"] = geo["city"]
            origin["lat"] = geo["lat"]
            origin["lon"] = geo["lon"]
            origin["location"] = f'{geo["city"]}, {geo["country"]}'

    attack_origins = sorted(
        origin_counts.values(),
        key=lambda item: (item["attempts"], item["suspicious"], item["source_ip"]),
        reverse=True,
    )

    api_counter: dict[str, dict] = {}
    for item in traffic_logs:
        api = api_counter.setdefault(
            item["path"],
            {
                "path": item["path"],
                "attempts": 0,
                "blocked": 0,
                "detections": 0,
                "latest_method": item["method"],
            },
        )
        api["attempts"] += 1
        if item["action"] == "blocked":
            api["blocked"] += 1
        if item["severity"] in {"critical", "high", "medium"}:
            api["detections"] += 1

    most_attacked_apis = sorted(
        api_counter.values(),
        key=lambda item: (item["attempts"], item["blocked"], item["path"]),
        reverse=True,
    )[:10]

    security_events = sorted(
        [_serialize_plan_log(row) for row in matched_plans]
        + [
            {
                "id": item["id"],
                "kind": "traffic_event",
                "timestamp": item["timestamp"],
                "request_id": item["request_id"],
                "source_ip": item["source_ip"],
                "method": item["method"],
                "path": item["path"],
                "severity": item["severity"],
                "action": item["action"],
                "attack_type": item["attack_type"],
                "status_code": item["status_code"],
            }
            for item in traffic_logs
            if item["severity"] in {"critical", "high", "medium"}
        ],
        key=lambda item: (item["timestamp"] or "", item["id"]),
        reverse=True,
    )[:limit]

    blocked_requests = sum(1 for item in traffic_logs if item["action"] == "blocked")
    suspicious_requests = sum(
        1 for item in traffic_logs if item["severity"] in {"critical", "high", "medium"}
    )
    severity_counter = Counter(item["severity"] for item in security_events)
    action_counter = Counter(item["action"] for item in security_events)

    summary = {
        "total_requests": len(matched_proxy) + len(matched_decoy),
        "total_logs": len(traffic_logs),
        "suspicious_requests": suspicious_requests,
        "blocked_requests": blocked_requests,
        "unique_source_ips": len(origin_counts),
        "last_updated": _utc_now_iso(),
        "severity_breakdown": {
            "critical": severity_counter.get("critical", 0),
            "high": severity_counter.get("high", 0),
            "medium": severity_counter.get("medium", 0),
            "low": severity_counter.get("low", 0),
        },
        "action_breakdown": {
            "blocked": action_counter.get("blocked", 0),
            "detected": action_counter.get("detected", 0),
            "allowed": action_counter.get("allowed", 0),
            "error": action_counter.get("error", 0),
        },
    }

    return {
        "traffic_logs": traffic_logs,
        "attack_origins": attack_origins,
        "most_attacked_apis": most_attacked_apis,
        "security_events": security_events,
        "summary": summary,
    }


def _collect_project_decoy_traffic(project: Project, db: Session, limit: int, range_name: str = "all") -> dict:
    patterns = _compile_project_path_patterns(project, db)
    time_cutoff = _resolve_time_window(range_name)
    if not patterns:
        return {
            "summary": {
                "total_interactions": 0,
                "active_sessions": 0,
                "unique_attackers": 0,
                "avg_response_time_ms": 0,
                "timeline_points": 0,
                "last_updated": _utc_now_iso(),
            },
            "timeline": [],
            "attack_type_breakdown": [],
            "top_decoy_targets": [],
            "sessions": [],
            "recent_interactions": [],
        }

    proxy_db = ProxySessionLocal()
    try:
        decoy_rows = (
            proxy_db.query(DecoyRequest)
            .order_by(DecoyRequest.id.desc())
            .limit(max(limit * 10, 500))
            .all()
        )
        plan_rows = (
            proxy_db.query(DeceptionPlanLog)
            .order_by(DeceptionPlanLog.id.desc())
            .limit(max(limit * 10, 500))
            .all()
        )
    finally:
        proxy_db.close()

    matched_decoys = [
        row for row in decoy_rows
        if _path_matches_project(row.path, patterns)
        and (time_cutoff is None or (row.timestamp and row.timestamp >= time_cutoff))
    ]
    matched_plans = [
        row for row in plan_rows
        if _path_matches_project(row.path, patterns)
        and (time_cutoff is None or (row.timestamp and row.timestamp >= time_cutoff))
    ]
    plan_by_request_id = {row.request_id: row for row in matched_plans}

    sessions: dict[str, dict] = {}
    attack_type_counter: Counter = Counter()
    path_counter: Counter = Counter()
    timeline_counter: Counter = Counter()
    response_times: list[int] = []
    recent_interactions: list[dict] = []

    for row in matched_decoys:
        session_key = row.session_id or f"request:{row.request_id}"
        plan = plan_by_request_id.get(row.request_id)
        timestamp = row.timestamp.isoformat() if row.timestamp else None
        attack_type = (
            (plan.attack_type if plan else None)
            or "unknown_suspicious"
        )
        plan_source = plan.plan_source if plan else "fallback"
        confidence = plan.confidence if plan and plan.confidence is not None else None
        geo = KNOWN_GEO_BY_IP.get((row.client_ip or "").strip(), {})

        session = sessions.setdefault(
            session_key,
            {
                "session_id": session_key,
                "source_ip": row.client_ip or "unknown",
                "country": geo.get("country_name") or geo.get("country"),
                "city": geo.get("city_name") or geo.get("city"),
                "attack_type": attack_type,
                "plan_source": plan_source,
                "confidence": confidence,
                "first_seen": timestamp,
                "last_seen": timestamp,
                "interactions": 0,
                "paths": Counter(),
                "methods": Counter(),
                "response_statuses": Counter(),
                "avg_response_time_ms": 0,
                "_response_times": [],
            },
        )

        session["attack_type"] = attack_type or session["attack_type"]
        session["plan_source"] = plan_source or session["plan_source"]
        if confidence is not None:
            session["confidence"] = confidence
        session["interactions"] += 1
        session["paths"][row.path or "unknown"] += 1
        session["methods"][row.method or "UNKNOWN"] += 1
        session["response_statuses"][str(row.response_status or "unknown")] += 1
        if row.response_time_ms is not None:
            session["_response_times"].append(row.response_time_ms)
            response_times.append(row.response_time_ms)
        if timestamp and (not session["first_seen"] or timestamp < session["first_seen"]):
            session["first_seen"] = timestamp
        if timestamp and (not session["last_seen"] or timestamp > session["last_seen"]):
            session["last_seen"] = timestamp

        attack_type_counter[attack_type or "unknown_suspicious"] += 1
        path_counter[row.path or "unknown"] += 1
        if row.timestamp:
            timeline_counter[row.timestamp.strftime("%Y-%m-%d %H:00")] += 1

        recent_interactions.append(
            {
                "id": row.request_id,
                "timestamp": timestamp,
                "source_ip": row.client_ip or "unknown",
                "method": row.method or "UNKNOWN",
                "path": row.path or "unknown",
                "response_status": row.response_status,
                "response_time_ms": row.response_time_ms,
                "session_id": session_key,
                "attack_type": attack_type,
                "plan_source": plan_source,
                "confidence": confidence,
                "status_label": "Decoy engaged",
                "location": (
                    f'{geo.get("city_name") or geo.get("city")}, {geo.get("country_name") or geo.get("country")}'
                    if (geo.get("country_name") or geo.get("country"))
                    else "Unknown"
                ),
            }
        )

    session_rows = []
    for session in sessions.values():
        avg_response = (
            round(sum(session["_response_times"]) / len(session["_response_times"]))
            if session["_response_times"]
            else 0
        )
        top_path = session["paths"].most_common(1)[0][0] if session["paths"] else "unknown"
        primary_method = session["methods"].most_common(1)[0][0] if session["methods"] else "UNKNOWN"
        primary_status = session["response_statuses"].most_common(1)[0][0] if session["response_statuses"] else "unknown"
        session_rows.append(
            {
                "session_id": session["session_id"],
                "source_ip": session["source_ip"],
                "country": session["country"],
                "city": session["city"],
                "attack_type": session["attack_type"],
                "plan_source": session["plan_source"],
                "confidence": session["confidence"],
                "first_seen": session["first_seen"],
                "last_seen": session["last_seen"],
                "interactions": session["interactions"],
                "top_path": top_path,
                "primary_method": primary_method,
                "primary_status": primary_status,
                "avg_response_time_ms": avg_response,
            }
        )

    session_rows.sort(
        key=lambda item: (
            item["last_seen"] or "",
            item["interactions"],
            item["session_id"],
        ),
        reverse=True,
    )

    timeline = [
        {"bucket": bucket, "hits": count}
        for bucket, count in sorted(timeline_counter.items())
    ]
    attack_type_breakdown = [
        {"attack_type": attack_type, "count": count}
        for attack_type, count in attack_type_counter.most_common()
    ]
    top_decoy_targets = [
        {"path": path, "hits": count}
        for path, count in path_counter.most_common(8)
    ]
    recent_interactions.sort(
        key=lambda item: (item["timestamp"] or "", item["id"]),
        reverse=True,
    )

    summary = {
        "total_interactions": len(matched_decoys),
        "active_sessions": len(session_rows),
        "unique_attackers": len({row.client_ip or "unknown" for row in matched_decoys}),
        "avg_response_time_ms": round(sum(response_times) / len(response_times)) if response_times else 0,
        "timeline_points": len(timeline),
        "top_attack_type": attack_type_breakdown[0]["attack_type"] if attack_type_breakdown else "none",
        "top_target": top_decoy_targets[0]["path"] if top_decoy_targets else "none",
        "last_updated": _utc_now_iso(),
        "range": (range_name or "all").lower(),
    }

    return {
        "summary": summary,
        "timeline": timeline,
        "attack_type_breakdown": attack_type_breakdown,
        "top_decoy_targets": top_decoy_targets,
        "sessions": session_rows[:limit],
        "recent_interactions": recent_interactions[:limit],
    }


def get_owned_project(project_id: str, db: Session, user: User) -> Project:
    project = (
        db.query(Project)
        .filter(Project.id == project_id, Project.user_id == user.id)
        .first()
    )
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


def project_summary(project: Project, db: Session) -> dict:
    endpoints = (
        db.query(EndpointInventory)
        .filter(EndpointInventory.project_id == project.id)
        .all()
    )
    risk_counts = Counter((endpoint.risk_level or "low").lower() for endpoint in endpoints)
    selected_count = sum(1 for endpoint in endpoints if endpoint.is_selected_for_decoy)

    decoys = (
        db.query(DecoyConfig)
        .filter(DecoyConfig.project_id == project.id)
        .all()
    )
    decoy_counts = Counter((decoy.review_status or "draft").lower() for decoy in decoys)
    disabled_decoys = sum(1 for decoy in decoys if not decoy.is_enabled)

    proxy_config = (
        db.query(ProxyConfig)
        .filter(ProxyConfig.project_id == project.id)
        .order_by(ProxyConfig.created_at.desc())
        .first()
    )
    proxy_payload = None
    proxy_url = None
    proxy_status = "not_configured"
    if proxy_config:
        proxy_url = generated_proxy_config(proxy_config)["proxy_url"]
        proxy_status = "active" if proxy_config.is_active else "inactive"
        proxy_payload = {
            "id": proxy_config.id,
            "backend_base_url": proxy_config.backend_base_url,
            "proxy_host": proxy_config.proxy_host,
            "listen_port": proxy_config.listen_port,
            "proxy_url": proxy_url,
            "is_active": proxy_config.is_active,
            "mode": proxy_config.mode,
        }

    return {
        "id": project.id,
        "user_id": project.user_id,
        "name": project.name,
        "customer_name": project.customer_name,
        "environment": project.environment or "Development",
        "source_type": project.source_type,
        "source_value": project.source_value,
        "onboarding_status": project.onboarding_status or "imported",
        "decoy_generation_status": project.decoy_generation_status or "not_started",
        "created_at": project.created_at,
        "updated_at": project.updated_at,
        "endpoint_count": len(endpoints),
        "selected_endpoint_count": selected_count,
        "risk_summary": {
            "high": risk_counts.get("high", 0),
            "medium": risk_counts.get("medium", 0),
            "low": risk_counts.get("low", 0),
        },
        "decoy_summary": {
            "total": len(decoys),
            "draft": decoy_counts.get("draft", 0),
            "deployed": decoy_counts.get("deployed", 0),
            "needs_review": decoy_counts.get("needs_review", 0),
            "disabled": disabled_decoys,
        },
        "proxy_status": proxy_status,
        "proxy_url": proxy_url,
        "backend_url": proxy_config.backend_base_url if proxy_config else None,
        "proxy_config": proxy_payload,
    }


@router.get("")
def list_user_projects(
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    projects = (
        db.query(Project)
        .filter(Project.user_id == user.id)
        .order_by(Project.updated_at.desc().nullslast(), Project.created_at.desc())
        .all()
    )
    return {
        "total_projects": len(projects),
        "projects": [project_summary(project, db) for project in projects],
    }


@router.post("")
def create_user_project(
    payload: ProjectCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    return onboarding_routes.create_project(payload=payload, db=db, user=user)


@router.get("/overview")
def get_user_project_dashboard(
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    return onboarding_routes.project_dashboard(db=db, user=user)


@router.get("/{project_id}")
def get_user_project(
    project_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    project = get_owned_project(project_id, db, user)
    return {"project": project_summary(project, db)}


@router.get("/{project_id}/summary")
def get_user_project_summary(
    project_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    project = get_owned_project(project_id, db, user)
    return {"summary": project_summary(project, db)}


@router.get("/{project_id}/endpoints")
def get_user_project_endpoints(
    project_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    return onboarding_routes.list_project_endpoints(project_id=project_id, db=db, user=user)


@router.patch("/endpoints/{endpoint_id}/select")
def update_endpoint_selection(
    endpoint_id: str,
    payload: EndpointSelectRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    return onboarding_routes.select_endpoint_for_decoy(
        endpoint_id=endpoint_id,
        payload=payload,
        db=db,
        user=user,
    )


@router.post("/{project_id}/proxy-config")
def save_user_project_proxy_config(
    project_id: str,
    payload: ProxyConfigCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    return onboarding_routes.upsert_proxy_config(
        project_id=project_id,
        payload=payload,
        db=db,
        user=user,
    )


@router.get("/{project_id}/proxy-config")
def get_user_project_proxy_config(
    project_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    return onboarding_routes.get_proxy_config(project_id=project_id, db=db, user=user)


@router.post("/{project_id}/proxy-config/test")
def test_user_project_proxy_config(
    project_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    return onboarding_routes.test_proxy_config(project_id=project_id, db=db, user=user)


@router.post("/{project_id}/proxy-config/apply")
def apply_user_project_proxy_config(
    project_id: str,
    payload: Optional[ProxyConfigCreate] = None,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    return onboarding_routes.apply_proxy_config(
        project_id=project_id,
        payload=payload,
        db=db,
        user=user,
    )


@router.post("/{project_id}/proxy-config/deactivate")
def deactivate_user_project_proxy_config(
    project_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    return onboarding_routes.deactivate_proxy_config(project_id=project_id, db=db, user=user)


@router.post("/{project_id}/decoys/generate")
def generate_user_project_decoys(
    project_id: str,
    payload: DecoyGenerateRequest = DecoyGenerateRequest(),
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    return onboarding_routes.generate_project_decoys(
        project_id=project_id,
        payload=payload,
        db=db,
        user=user,
    )


@router.get("/{project_id}/decoys")
def get_user_project_decoys(
    project_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    return onboarding_routes.list_project_decoys(project_id=project_id, db=db, user=user)


@router.patch("/{project_id}/decoys/{decoy_id}")
def update_user_project_decoy(
    project_id: str,
    decoy_id: str,
    payload: DecoyUpdateRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    return onboarding_routes.update_project_decoy(
        project_id=project_id,
        decoy_id=decoy_id,
        payload=payload,
        db=db,
        user=user,
    )


@router.post("/{project_id}/decoys/deploy")
def deploy_user_project_decoys(
    project_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    return onboarding_routes.deploy_project_decoys(project_id=project_id, db=db, user=user)


@router.post("/{project_id}/decoy-configs")
def create_user_project_decoy_config(
    project_id: str,
    payload: DecoyConfigCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    return onboarding_routes.create_decoy_config(
        project_id=project_id,
        payload=payload,
        db=db,
        user=user,
    )


@router.get("/{project_id}/decoy-configs")
def list_user_project_decoy_configs(
    project_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    return onboarding_routes.list_decoy_configs(project_id=project_id, db=db, user=user)


@router.get("/{project_id}/traffic")
@router.get("/{project_id}/traffic/logs")
def get_user_project_traffic(
    project_id: str,
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    project = get_owned_project(project_id, db, user)
    analytics = _collect_project_traffic(project, db, limit)
    return {
        "project_id": project_id,
        **analytics,
        "logs": analytics["traffic_logs"],
        "items": analytics["traffic_logs"],
        "total_traffic_logs": analytics["summary"]["total_requests"],
        "count": analytics["summary"]["total_requests"],
    }


@router.get("/{project_id}/attack-origins")
def get_user_project_attack_origins(
    project_id: str,
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    project = get_owned_project(project_id, db, user)
    analytics = _collect_project_traffic(project, db, limit)
    return {
        "project_id": project_id,
        "attack_origins": analytics["attack_origins"],
        "items": analytics["attack_origins"],
        "count": len(analytics["attack_origins"]),
        "last_updated": analytics["summary"]["last_updated"],
    }


@router.get("/{project_id}/most-attacked")
def get_user_project_most_attacked_apis(
    project_id: str,
    limit: int = Query(default=10, ge=1, le=100),
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    project = get_owned_project(project_id, db, user)
    analytics = _collect_project_traffic(project, db, max(limit, 100))
    items = analytics["most_attacked_apis"][:limit]
    return {
        "project_id": project_id,
        "most_attacked_apis": items,
        "items": items,
        "count": len(items),
        "last_updated": analytics["summary"]["last_updated"],
    }


@router.get("/{project_id}/alerts")
@router.get("/{project_id}/security-events")
def get_user_project_alerts(
    project_id: str,
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    project = get_owned_project(project_id, db, user)
    analytics = _collect_project_traffic(project, db, limit)
    summary = analytics["summary"]
    return {
        "project_id": project_id,
        "alerts": analytics["security_events"],
        "security_events": analytics["security_events"],
        "items": analytics["security_events"],
        "total_alerts": len(analytics["security_events"]),
        "blocked": summary["action_breakdown"]["blocked"],
        "all_detections": summary["suspicious_requests"],
        "severity_breakdown": summary["severity_breakdown"],
        "last_updated": summary["last_updated"],
    }


@router.get("/{project_id}/monitor")
@router.get("/{project_id}/dashboard")
def get_user_project_monitor(
    project_id: str,
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    project = get_owned_project(project_id, db, user)
    analytics = _collect_project_traffic(project, db, limit)
    summary = analytics["summary"]
    return {
        "project_id": project_id,
        "summary": summary,
        "traffic_logs": analytics["traffic_logs"],
        "attack_origins": analytics["attack_origins"],
        "most_attacked_apis": analytics["most_attacked_apis"],
        "alerts": analytics["security_events"],
        "security_events": analytics["security_events"],
        "protection_status": {
            "proxy": "active",
            "protected_url": project_summary(project, db)["proxy_url"],
            "backend_url": project_summary(project, db)["backend_url"],
            "decoys": project.decoy_generation_status or "not_started",
        },
        "counts": {
            "traffic_logs": summary["total_requests"],
            "attack_origins": len(analytics["attack_origins"]),
            "alerts": len(analytics["security_events"]),
            "blocked": summary["blocked_requests"],
            "detections": summary["suspicious_requests"],
        },
        "last_updated": summary["last_updated"],
    }


@router.get("/{project_id}/decoy-traffic")
def get_user_project_decoy_traffic(
    project_id: str,
    limit: int = Query(default=100, ge=1, le=500),
    range: str = Query(default="all", pattern="^(all|24h|7d|30d)$"),
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    project = get_owned_project(project_id, db, user)
    analytics = _collect_project_decoy_traffic(project, db, limit, range)
    return {
        "project_id": project_id,
        **analytics,
    }


@router.patch("/{project_id}")
def update_user_project(
    project_id: str,
    payload: ProjectUpdateRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    project = get_owned_project(project_id, db, user)
    data = payload.model_dump(exclude_unset=True)
    for field, value in data.items():
        if value is not None:
            setattr(project, field, value)

    db.commit()
    db.refresh(project)
    return {
        "message": "Project updated",
        "project": project_summary(project, db),
    }


@router.delete("/{project_id}")
def delete_user_project(
    project_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    project = get_owned_project(project_id, db, user)
    db.delete(project)
    db.commit()
    return {"message": "Project deleted", "project_id": project_id}

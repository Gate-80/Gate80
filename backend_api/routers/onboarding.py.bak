from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
import uuid
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend_api.db.database import get_db
from backend_api.db.models import Project, EndpointInventory, DecoyConfig, ProxyConfig, User
from backend_api.decoy_generator import generate_decoy_for_endpoint
from backend_api.openapi_parser import load_openapi_document, parse_openapi_endpoints
from backend_api.risk_score_api import score_endpoint
from backend_api.routers.user_authentication import require_user


router = APIRouter(prefix="/onboarding", tags=["onboarding"])

RISK_ORDER = {"high": 0, "medium": 1, "low": 2}
PROJECT_ROOT = Path(__file__).resolve().parents[2]
RUNNING_PROXY_PROCESSES: dict[str, subprocess.Popen] = {}


def generate_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def risk_sort_key(endpoint: EndpointInventory) -> tuple[int, int, str, str]:
    try:
        score = int(endpoint.risk_score or 0)
    except (TypeError, ValueError):
        score = 0

    return (
        RISK_ORDER.get((endpoint.risk_level or "low").lower(), 99),
        -score,
        endpoint.method or "",
        endpoint.path or "",
    )


def risk_summary(endpoints: list[EndpointInventory]) -> dict[str, int]:
    summary = {"high": 0, "medium": 0, "low": 0}
    for endpoint in endpoints:
        risk = (endpoint.risk_level or "low").lower()
        if risk in summary:
            summary[risk] += 1
    return summary


def normalize_base_url(value: str) -> str:
    url = (value or "").strip().rstrip("/")
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(
            status_code=400,
            detail="backend_base_url must be a valid http:// or https:// URL.",
        )
    return url


def proxy_config_payload(config: ProxyConfig) -> dict:
    return {
        "id": config.id,
        "project_id": config.project_id,
        "backend_base_url": config.backend_base_url,
        "proxy_host": config.proxy_host,
        "listen_port": config.listen_port,
        "api_key": config.api_key,
        "mode": config.mode,
        "is_active": config.is_active,
        "created_at": config.created_at,
        "updated_at": config.updated_at,
    }


def generated_proxy_config(config: ProxyConfig) -> dict:
    proxy_url = f"http://{config.proxy_host or '127.0.0.1'}:{config.listen_port or '8080'}"
    nginx_config = f"""server {{
    listen {config.listen_port or "8080"};

    location / {{
        proxy_pass {config.backend_base_url};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-From-Proxy 1;
    }}
}}"""

    return {
        "proxy_url": proxy_url,
        "required_header": "X-From-Proxy: 1",
        "nginx_config": nginx_config,
        "gate80_env": {
            "BACKEND_URL": config.backend_base_url,
            "PROXY_HOST": config.proxy_host or "127.0.0.1",
            "PROXY_PORT": config.listen_port or "8080",
            "GATE80_REQUIRED_HEADER": "X-From-Proxy",
        },
    }


def decoy_payload(decoy: DecoyConfig) -> dict:
    endpoint = decoy.endpoint
    return {
        "id": decoy.id,
        "project_id": decoy.project_id,
        "endpoint_id": decoy.endpoint_id,
        "created_by_user_id": decoy.created_by_user_id,
        "name": decoy.name,
        "description": decoy.description,
        "decoy_type": decoy.decoy_type,
        "status_code": decoy.status_code,
        "response_template": decoy.response_template,
        "headers_template": decoy.headers_template,
        "trigger_condition": decoy.trigger_condition,
        "delay_ms": decoy.delay_ms,
        "generation_source": decoy.generation_source,
        "review_status": decoy.review_status,
        "is_enabled": decoy.is_enabled,
        "created_at": decoy.created_at,
        "updated_at": decoy.updated_at,
        "endpoint": {
            "method": endpoint.method,
            "path": endpoint.path,
            "tag": endpoint.tag,
            "risk_level": endpoint.risk_level,
            "risk_score": endpoint.risk_score,
        } if endpoint else None,
    }


def get_project_or_404(project_id: str, db: Session, user: Optional[User] = None) -> Project:
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if user is not None and project.user_id != user.id:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


def parse_port(value: str) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="listen_port must be a number.")

    if port < 1 or port > 65535:
        raise HTTPException(status_code=400, detail="listen_port must be between 1 and 65535.")
    return port


def is_process_running(process: subprocess.Popen | None) -> bool:
    return process is not None and process.poll() is None


def is_port_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


def wait_for_port(host: str, port: int, timeout_sec: float = 5.0) -> bool:
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        if is_port_open(host, port):
            return True
        time.sleep(0.2)
    return False


def get_proxy_config_or_404(project_id: str, db: Session) -> ProxyConfig:
    config = (
        db.query(ProxyConfig)
        .filter(ProxyConfig.project_id == project_id)
        .first()
    )
    if not config:
        raise HTTPException(status_code=404, detail="Proxy configuration not found")
    return config


# -----------------------------
# Schemas
# -----------------------------
class ProjectCreate(BaseModel):
    name: str
    customer_name: str
    environment: str = "Development"
    source_type: str
    source_value: str


class EndpointSelectRequest(BaseModel):
    is_selected_for_decoy: bool


class DecoyConfigCreate(BaseModel):
    endpoint_id: str
    decoy_type: str
    status_code: str = "200"
    response_template: Optional[Dict[str, Any]] = None
    delay_ms: str = "0"
    is_enabled: bool = True


class ProxyConfigCreate(BaseModel):
    backend_base_url: str
    proxy_host: str = "127.0.0.1"
    listen_port: str = "8080"
    api_key: Optional[str] = None
    mode: str = "reverse_proxy"
    is_active: bool = True


class DecoyGenerateRequest(BaseModel):
    replace_existing_drafts: bool = False
    deploy_immediately: bool = True


class DecoyUpdateRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    decoy_type: Optional[str] = None
    status_code: Optional[str] = None
    response_template: Optional[Dict[str, Any]] = None
    headers_template: Optional[Dict[str, Any]] = None
    trigger_condition: Optional[Dict[str, Any]] = None
    delay_ms: Optional[str] = None
    review_status: Optional[str] = None
    is_enabled: Optional[bool] = None


# -----------------------------
# Routes
# -----------------------------
@router.post("/projects")
def create_project(
    payload: ProjectCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    project = Project(
        id=generate_id("proj"),
        user_id=user.id,
        name=payload.name,
        customer_name=payload.customer_name,
        environment=payload.environment,
        source_type=payload.source_type,
        source_value=payload.source_value,
    )
    db.add(project)
    db.commit()
    db.refresh(project)

    return {
        "message": "Project created successfully",
        "project": {
            "id": project.id,
            "user_id": project.user_id,
            "name": project.name,
            "customer_name": project.customer_name,
            "environment": project.environment,
            "source_type": project.source_type,
            "source_value": project.source_value,
            "created_at": project.created_at,
        }
    }


@router.get("/projects")
def list_projects(
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    projects = (
        db.query(Project)
        .filter(Project.user_id == user.id)
        .order_by(Project.created_at.desc())
        .all()
    )
    return {
        "projects": [
            {
                "id": p.id,
                "user_id": p.user_id,
                "name": p.name,
                "customer_name": p.customer_name,
                "environment": p.environment,
                "source_type": p.source_type,
                "source_value": p.source_value,
                "created_at": p.created_at,
            }
            for p in projects
        ]
    }


@router.get("/dashboard")
def project_dashboard(
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    projects = (
        db.query(Project)
        .filter(Project.user_id == user.id)
        .order_by(Project.created_at.desc())
        .all()
    )
    project_ids = [project.id for project in projects]

    endpoint_counts = dict(
        db.query(EndpointInventory.project_id, func.count(EndpointInventory.id))
        .filter(EndpointInventory.project_id.in_(project_ids))
        .group_by(EndpointInventory.project_id)
        .all()
    ) if project_ids else {}

    high_risk_counts = dict(
        db.query(EndpointInventory.project_id, func.count(EndpointInventory.id))
        .filter(
            EndpointInventory.project_id.in_(project_ids),
            EndpointInventory.risk_level.in_(("high", "critical")),
        )
        .group_by(EndpointInventory.project_id)
        .all()
    ) if project_ids else {}

    selected_counts = dict(
        db.query(EndpointInventory.project_id, func.count(EndpointInventory.id))
        .filter(
            EndpointInventory.project_id.in_(project_ids),
            EndpointInventory.is_selected_for_decoy.is_(True),
        )
        .group_by(EndpointInventory.project_id)
        .all()
    ) if project_ids else {}

    decoy_counts = dict(
        db.query(DecoyConfig.project_id, func.count(DecoyConfig.id))
        .filter(DecoyConfig.project_id.in_(project_ids))
        .group_by(DecoyConfig.project_id)
        .all()
    ) if project_ids else {}

    active_proxy_counts = dict(
        db.query(ProxyConfig.project_id, func.count(ProxyConfig.id))
        .filter(
            ProxyConfig.project_id.in_(project_ids),
            ProxyConfig.is_active.is_(True),
        )
        .group_by(ProxyConfig.project_id)
        .all()
    ) if project_ids else {}

    rows = []
    for project in projects:
        rows.append({
            "id": project.id,
            "user_id": project.user_id,
            "name": project.name,
            "customer_name": project.customer_name,
            "source_type": project.source_type,
            "source_value": project.source_value,
            "created_at": project.created_at,
            "total_endpoints": endpoint_counts.get(project.id, 0),
            "high_risk_endpoints": high_risk_counts.get(project.id, 0),
            "selected_for_decoy": selected_counts.get(project.id, 0),
            "decoy_configs": decoy_counts.get(project.id, 0),
            "active_proxy_configs": active_proxy_counts.get(project.id, 0),
        })

    return {
        "user": {
            "id": user.id,
            "full_name": user.full_name,
            "email": user.email,
            "city": user.city,
            "is_verified": user.is_verified,
        },
        "summary": {
            "total_projects": len(projects),
            "total_endpoints": sum(endpoint_counts.values()),
            "high_risk_endpoints": sum(high_risk_counts.values()),
            "selected_for_decoy": sum(selected_counts.values()),
            "decoy_configs": sum(decoy_counts.values()),
            "active_proxy_configs": sum(active_proxy_counts.values()),
        },
        "projects": rows,
    }


@router.post("/parse-openapi-file")
async def parse_openapi_file(
    project_name: str = Form(...),
    customer_name: str = Form(...),
    environment: str = Form("Development"),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    raw = (await file.read()).decode("utf-8")

    try:
        spec = load_openapi_document(raw)
        endpoints = parse_openapi_endpoints(spec)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e

    if not endpoints:
        raise HTTPException(status_code=400, detail="No endpoints found in OpenAPI file.")

    project = Project(
        id=generate_id("proj"),
        user_id=user.id,
        name=project_name,
        customer_name=customer_name,
        environment=environment,
        source_type="openapi_file",
        source_value=file.filename,
    )
    db.add(project)
    db.flush()

    created_endpoints = []
    for ep in endpoints:
        score, risk = score_endpoint(
            ep["path"], ep["method"], ep["tag"], ep["requires_auth"]
        )

        endpoint = EndpointInventory(
            id=generate_id("ep"),
            project_id=project.id,
            path=ep["path"],
            method=ep["method"],
            summary=ep["summary"],
            tag=ep["tag"],
            requires_auth=ep["requires_auth"],
            request_schema_json=ep["request_schema_json"],
            response_schema_json=ep["response_schema_json"],
            risk_score=str(score),
            risk_level=risk,
            is_selected_for_decoy=(risk == "high"),
        )
        db.add(endpoint)
        created_endpoints.append(endpoint)

    db.commit()
    db.refresh(project)
    created_endpoints.sort(key=risk_sort_key)

    return {
        "message": "OpenAPI parsed and project created successfully",
        "project": {
            "id": project.id,
            "user_id": project.user_id,
            "name": project.name,
            "customer_name": project.customer_name,
            "environment": project.environment,
            "source_type": project.source_type,
            "source_value": project.source_value,
            "created_at": project.created_at,
        },
        "total_endpoints": len(created_endpoints),
        "risk_summary": risk_summary(created_endpoints),
        "endpoints": [
            {
                "id": ep.id,
                "path": ep.path,
                "method": ep.method,
                "summary": ep.summary,
                "tag": ep.tag,
                "requires_auth": ep.requires_auth,
                "risk_score": ep.risk_score,
                "risk_level": ep.risk_level,
                "is_selected_for_decoy": ep.is_selected_for_decoy,
            }
            for ep in created_endpoints
        ]
    }


@router.get("/projects/{project_id}/endpoints")
def list_project_endpoints(
    project_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    get_project_or_404(project_id, db, user)

    endpoints = (
        db.query(EndpointInventory)
        .filter(EndpointInventory.project_id == project_id)
        .all()
    )
    endpoints.sort(key=risk_sort_key)

    return {
        "project_id": project_id,
        "total_endpoints": len(endpoints),
        "risk_summary": risk_summary(endpoints),
        "endpoints": [
            {
                "id": ep.id,
                "path": ep.path,
                "method": ep.method,
                "summary": ep.summary,
                "tag": ep.tag,
                "requires_auth": ep.requires_auth,
                "request_schema_json": ep.request_schema_json,
                "response_schema_json": ep.response_schema_json,
                "risk_score": ep.risk_score,
                "risk_level": ep.risk_level,
                "is_selected_for_decoy": ep.is_selected_for_decoy,
                "created_at": ep.created_at,
            }
            for ep in endpoints
        ]
    }


@router.patch("/endpoints/{endpoint_id}/select")
def select_endpoint_for_decoy(
    endpoint_id: str,
    payload: EndpointSelectRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    endpoint = db.query(EndpointInventory).filter(EndpointInventory.id == endpoint_id).first()
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    get_project_or_404(endpoint.project_id, db, user)

    endpoint.is_selected_for_decoy = payload.is_selected_for_decoy
    db.commit()
    db.refresh(endpoint)

    return {
        "message": "Endpoint selection updated",
        "endpoint": {
            "id": endpoint.id,
            "project_id": endpoint.project_id,
            "path": endpoint.path,
            "method": endpoint.method,
            "is_selected_for_decoy": endpoint.is_selected_for_decoy,
        }
    }


@router.post("/projects/{project_id}/proxy-config")
def upsert_proxy_config(
    project_id: str,
    payload: ProxyConfigCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    get_project_or_404(project_id, db, user)
    backend_base_url = normalize_base_url(payload.backend_base_url)

    config = (
        db.query(ProxyConfig)
        .filter(ProxyConfig.project_id == project_id)
        .first()
    )

    if config is None:
        config = ProxyConfig(
            id=generate_id("proxy"),
            project_id=project_id,
        )
        db.add(config)

    config.backend_base_url = backend_base_url
    config.proxy_host = (payload.proxy_host or "127.0.0.1").strip()
    config.listen_port = str(payload.listen_port or "8080").strip()
    config.api_key = payload.api_key
    config.mode = payload.mode or "reverse_proxy"
    config.is_active = payload.is_active

    db.commit()
    db.refresh(config)

    return {
        "message": "Proxy configuration saved",
        "proxy_config": proxy_config_payload(config),
        "generated_config": generated_proxy_config(config),
    }


@router.get("/projects/{project_id}/proxy-config")
def get_proxy_config(
    project_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    get_project_or_404(project_id, db, user)
    config = get_proxy_config_or_404(project_id, db)

    return {
        "project_id": project_id,
        "proxy_config": proxy_config_payload(config),
        "generated_config": generated_proxy_config(config),
    }


@router.post("/projects/{project_id}/proxy-config/test")
def test_proxy_config(
    project_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    get_project_or_404(project_id, db, user)
    config = get_proxy_config_or_404(project_id, db)

    health_url = f"{config.backend_base_url.rstrip('/')}/health"
    request = urllib.request.Request(
        health_url,
        method="GET",
        headers={"X-From-Proxy": "1"},
    )

    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            status_code = response.status
            reachable = 200 <= status_code < 500
    except urllib.error.HTTPError as exc:
        status_code = exc.code
        reachable = 200 <= status_code < 500
    except urllib.error.URLError as exc:
        return {
            "project_id": project_id,
            "reachable": False,
            "target_url": health_url,
            "error": str(exc.reason),
        }
    except TimeoutError:
        return {
            "project_id": project_id,
            "reachable": False,
            "target_url": health_url,
            "error": "Connection timed out",
        }

    return {
        "project_id": project_id,
        "reachable": reachable,
        "target_url": health_url,
        "status_code": status_code,
        "required_header": "X-From-Proxy: 1",
    }


@router.post("/projects/{project_id}/proxy-config/apply")
def apply_proxy_config(
    project_id: str,
    payload: Optional[ProxyConfigCreate] = None,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    get_project_or_404(project_id, db, user)

    if payload is not None:
        backend_base_url = normalize_base_url(payload.backend_base_url)
        config = (
            db.query(ProxyConfig)
            .filter(ProxyConfig.project_id == project_id)
            .first()
        )

        if config is None:
            config = ProxyConfig(
                id=generate_id("proxy"),
                project_id=project_id,
            )
            db.add(config)

        config.backend_base_url = backend_base_url
        config.proxy_host = (payload.proxy_host or "127.0.0.1").strip()
        config.listen_port = str(payload.listen_port or "8080").strip()
        config.api_key = payload.api_key
        config.mode = payload.mode or "reverse_proxy"
        config.is_active = payload.is_active
        db.commit()
        db.refresh(config)
    else:
        config = get_proxy_config_or_404(project_id, db)

    port = parse_port(config.listen_port or "8080")
    host = config.proxy_host or "127.0.0.1"

    process = RUNNING_PROXY_PROCESSES.get(project_id)
    if is_process_running(process):
        return {
            "message": "Proxy is already running",
            "project_id": project_id,
            "running": True,
            "pid": process.pid,
            "proxy_url": generated_proxy_config(config)["proxy_url"],
            "backend_url": config.backend_base_url,
            "backend_base_url": config.backend_base_url,
        }

    if is_port_open(host, port):
        return {
            "message": "Proxy port is already in use",
            "project_id": project_id,
            "running": True,
            "pid": None,
            "proxy_url": generated_proxy_config(config)["proxy_url"],
            "backend_url": config.backend_base_url,
            "backend_base_url": config.backend_base_url,
            "warning": f"{host}:{port} is already accepting connections.",
        }

    env = os.environ.copy()
    env.update({
        "BACKEND_URL": config.backend_base_url,
        "DECOY_URL": env.get("DECOY_URL", "http://127.0.0.1:8001"),
        "BACKEND_DB_PATH": env.get("BACKEND_DB_PATH", str(PROJECT_ROOT / "digital_wallet.db")),
        "DECOY_DB_PATH": env.get("DECOY_DB_PATH", str(PROJECT_ROOT / "decoy_wallet.db")),
    })

    command = [
        sys.executable,
        "-m",
        "uvicorn",
        "proxy.main:app",
        "--host",
        host,
        "--port",
        str(port),
    ]

    try:
        process = subprocess.Popen(
            command,
            cwd=str(PROJECT_ROOT),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError as exc:
        raise HTTPException(status_code=500, detail=f"Failed to start proxy: {exc}") from exc

    RUNNING_PROXY_PROCESSES[project_id] = process

    if not wait_for_port(host, port):
        return {
            "message": "Proxy start was requested, but the port did not become ready in time",
            "project_id": project_id,
            "running": is_process_running(process),
            "pid": process.pid,
            "proxy_url": generated_proxy_config(config)["proxy_url"],
            "backend_url": config.backend_base_url,
            "backend_base_url": config.backend_base_url,
        }

    return {
        "message": "Proxy started",
        "project_id": project_id,
        "running": True,
        "pid": process.pid,
        "proxy_url": generated_proxy_config(config)["proxy_url"],
        "backend_url": config.backend_base_url,
        "backend_base_url": config.backend_base_url,
        "command": " ".join(command),
    }


@router.post("/projects/{project_id}/proxy-config/deactivate")
def deactivate_proxy_config(
    project_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    get_project_or_404(project_id, db, user)
    config = get_proxy_config_or_404(project_id, db)

    process = RUNNING_PROXY_PROCESSES.pop(project_id, None)
    stopped_process = False
    warning = None

    if is_process_running(process):
        process.terminate()
        try:
            process.wait(timeout=3)
            stopped_process = True
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
            stopped_process = True

    config.is_active = False
    db.commit()
    db.refresh(config)

    port = parse_port(config.listen_port or "8080")
    host = config.proxy_host or "127.0.0.1"
    still_open = is_port_open(host, port)
    if still_open and not stopped_process:
        warning = f"{host}:{port} is still accepting connections, but it was not started by this backend process."

    return {
        "message": "Gate80 protection is inactive",
        "project_id": project_id,
        "running": still_open,
        "stopped_process": stopped_process,
        "proxy_url": generated_proxy_config(config)["proxy_url"],
        "backend_url": config.backend_base_url,
        "backend_base_url": config.backend_base_url,
        "proxy_config": proxy_config_payload(config),
        "warning": warning,
    }


@router.post("/projects/{project_id}/decoys/generate")
def generate_project_decoys(
    project_id: str,
    payload: DecoyGenerateRequest = DecoyGenerateRequest(),
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    project = get_project_or_404(project_id, db, user)
    project.decoy_generation_status = "generating"
    db.flush()

    selected_endpoints = (
        db.query(EndpointInventory)
        .filter(
            EndpointInventory.project_id == project_id,
            EndpointInventory.is_selected_for_decoy == True,
        )
        .all()
    )
    selected_endpoints.sort(key=risk_sort_key)

    if not selected_endpoints:
        project.decoy_generation_status = "not_started"
        db.commit()
        raise HTTPException(status_code=400, detail="Select at least one endpoint before generating decoys.")

    generated = []
    skipped = []
    deployed = True

    for endpoint in selected_endpoints:
        existing = (
            db.query(DecoyConfig)
            .filter(
                DecoyConfig.project_id == project_id,
                DecoyConfig.endpoint_id == endpoint.id,
            )
            .all()
        )

        if existing and not payload.replace_existing_drafts:
            for decoy in existing:
                decoy.review_status = "deployed"
                decoy.is_enabled = True
            skipped.extend(existing)
            continue

        if existing and payload.replace_existing_drafts:
            for decoy in existing:
                if (decoy.review_status or "draft") != "deployed":
                    db.delete(decoy)
            db.flush()

        template = generate_decoy_for_endpoint(endpoint)
        decoy = DecoyConfig(
            id=generate_id("decoy"),
            project_id=project_id,
            endpoint_id=endpoint.id,
            created_by_user_id=user.id,
            name=template["name"],
            description=template["description"],
            decoy_type=template["decoy_type"],
            status_code=template["status_code"],
            response_template=template["response_template"],
            headers_template=template["headers_template"],
            trigger_condition=template["trigger_condition"],
            delay_ms=template["delay_ms"],
            generation_source="auto",
            review_status="deployed" if deployed else "draft",
            is_enabled=deployed,
        )
        db.add(decoy)
        generated.append(decoy)

    project.decoy_generation_status = "deployed" if deployed else "draft_ready"
    db.commit()

    for decoy in generated:
        db.refresh(decoy)

    return {
        "message": "Decoys generated",
        "project_id": project_id,
        "decoy_generation_status": project.decoy_generation_status,
        "generated_count": len(generated),
        "skipped_count": len(skipped),
        "decoys": [decoy_payload(decoy) for decoy in generated],
    }


@router.get("/projects/{project_id}/decoys")
def list_project_decoys(
    project_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    project = get_project_or_404(project_id, db, user)
    decoys = (
        db.query(DecoyConfig)
        .filter(DecoyConfig.project_id == project_id)
        .order_by(DecoyConfig.created_at.desc())
        .all()
    )
    changed = False
    for decoy in decoys:
        if decoy.review_status != "deployed" or not decoy.is_enabled:
            decoy.review_status = "deployed"
            decoy.is_enabled = True
            changed = True
    if changed:
        project.decoy_generation_status = "deployed"
        db.commit()
        for decoy in decoys:
            db.refresh(decoy)

    summary = {"draft": 0, "deployed": 0, "disabled": 0, "needs_review": 0}
    for decoy in decoys:
        status = decoy.review_status or "deployed"
        if status in summary:
            summary[status] += 1
        if not decoy.is_enabled:
            summary["disabled"] += 1

    return {
        "project_id": project_id,
        "decoy_generation_status": project.decoy_generation_status,
        "total_decoys": len(decoys),
        "summary": summary,
        "decoys": [decoy_payload(decoy) for decoy in decoys],
    }


@router.patch("/projects/{project_id}/decoys/{decoy_id}")
def update_project_decoy(
    project_id: str,
    decoy_id: str,
    payload: DecoyUpdateRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    get_project_or_404(project_id, db, user)
    decoy = (
        db.query(DecoyConfig)
        .filter(DecoyConfig.id == decoy_id, DecoyConfig.project_id == project_id)
        .first()
    )
    if not decoy:
        raise HTTPException(status_code=404, detail="Decoy not found")

    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(decoy, field, value)

    decoy.generation_source = "manual"
    db.commit()
    db.refresh(decoy)

    return {
        "message": "Decoy updated",
        "decoy": decoy_payload(decoy),
    }


@router.post("/projects/{project_id}/decoys/deploy")
def deploy_project_decoys(
    project_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    project = get_project_or_404(project_id, db, user)
    decoys = (
        db.query(DecoyConfig)
        .filter(DecoyConfig.project_id == project_id)
        .all()
    )
    if not decoys:
        raise HTTPException(status_code=400, detail="Generate decoys before deploying them.")

    for decoy in decoys:
        decoy.review_status = "deployed"
        decoy.is_enabled = True

    project.decoy_generation_status = "deployed"
    db.commit()

    return {
        "message": "Decoys deployed",
        "project_id": project_id,
        "deployed_count": len(decoys),
        "decoy_generation_status": project.decoy_generation_status,
    }


@router.post("/projects/{project_id}/decoy-configs")
def create_decoy_config(
    project_id: str,
    payload: DecoyConfigCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    get_project_or_404(project_id, db, user)

    endpoint = (
        db.query(EndpointInventory)
        .filter(
            EndpointInventory.id == payload.endpoint_id,
            EndpointInventory.project_id == project_id,
        )
        .first()
    )
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found for this project")

    decoy = DecoyConfig(
        id=generate_id("decoy"),
        project_id=project_id,
        endpoint_id=payload.endpoint_id,
        decoy_type=payload.decoy_type,
        status_code=payload.status_code,
        response_template=payload.response_template,
        delay_ms=payload.delay_ms,
        is_enabled=payload.is_enabled,
    )
    db.add(decoy)
    db.commit()
    db.refresh(decoy)

    return {
        "message": "Decoy config created successfully",
        "decoy_config": {
            "id": decoy.id,
            "project_id": decoy.project_id,
            "endpoint_id": decoy.endpoint_id,
            "decoy_type": decoy.decoy_type,
            "status_code": decoy.status_code,
            "response_template": decoy.response_template,
            "delay_ms": decoy.delay_ms,
            "is_enabled": decoy.is_enabled,
            "created_at": decoy.created_at,
        }
    }


@router.get("/projects/{project_id}/decoy-configs")
def list_decoy_configs(
    project_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    get_project_or_404(project_id, db, user)

    decoys = (
        db.query(DecoyConfig)
        .filter(DecoyConfig.project_id == project_id)
        .order_by(DecoyConfig.created_at.desc())
        .all()
    )

    return {
        "project_id": project_id,
        "total_decoy_configs": len(decoys),
        "decoy_configs": [
            {
                "id": d.id,
                "project_id": d.project_id,
                "endpoint_id": d.endpoint_id,
                "decoy_type": d.decoy_type,
                "status_code": d.status_code,
                "response_template": d.response_template,
                "delay_ms": d.delay_ms,
                "is_enabled": d.is_enabled,
                "created_at": d.created_at,
            }
            for d in decoys
        ]
    }

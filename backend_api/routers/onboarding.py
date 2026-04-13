from __future__ import annotations

import json
import uuid
from typing import Any, Dict, List, Optional

import yaml
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend_api.db.database import get_db
from backend_api.db.models import Project, EndpointInventory, DecoyConfig


router = APIRouter(prefix="/onboarding", tags=["onboarding"])


# -----------------------------
# Helpers
# -----------------------------
HIGH_RISK_KEYWORDS = {
    "login", "signin", "sign-in", "auth", "password", "reset",
    "transfer", "withdraw", "payment", "pay", "bill",
    "wallet", "admin", "token", "otp", "verify"
}

LOW_RISK_KEYWORDS = {
    "health", "hello", "status", "ping", "docs", "swagger", "openapi"
}


def generate_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def load_openapi_document(raw_text: str) -> Dict[str, Any]:
    try:
        return json.loads(raw_text)
    except json.JSONDecodeError:
        try:
            return yaml.safe_load(raw_text)
        except Exception as e:
            raise ValueError(f"Invalid JSON/YAML OpenAPI document: {e}") from e


def parse_openapi_endpoints(spec: Dict[str, Any]) -> List[Dict[str, Any]]:
    paths = spec.get("paths", {})
    endpoints: List[Dict[str, Any]] = []

    if not isinstance(paths, dict):
        return endpoints

    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue

        for method, operation in methods.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete", "head", "options"}:
                continue

            operation = operation or {}
            tags = operation.get("tags", [])
            summary = operation.get("summary") or operation.get("description") or ""
            security = operation.get("security", spec.get("security", []))
            requires_auth = bool(security)

            request_schema = {}
            request_body = operation.get("requestBody", {})
            content = request_body.get("content", {})
            if "application/json" in content:
                request_schema = content["application/json"].get("schema", {})

            response_schema = {}
            responses = operation.get("responses", {})
            for _, response in responses.items():
                response_content = response.get("content", {})
                if "application/json" in response_content:
                    response_schema = response_content["application/json"].get("schema", {})
                    break

            endpoints.append({
                "path": path,
                "method": method.upper(),
                "summary": summary,
                "tag": tags[0] if tags else "uncategorized",
                "requires_auth": requires_auth,
                "request_schema_json": request_schema,
                "response_schema_json": response_schema,
            })

    return endpoints


def score_endpoint(path: str, method: str, tag: str, requires_auth: bool) -> tuple[int, str]:
    score = 0
    target = f"{method} {path} {tag}".lower()

    for word in HIGH_RISK_KEYWORDS:
        if word in target:
            score += 25

    for word in LOW_RISK_KEYWORDS:
        if word in target:
            score -= 20

    if requires_auth:
        score += 10

    if method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
        score += 10

    if score >= 40:
        return score, "high"
    if score >= 15:
        return score, "medium"
    return score, "low"


# -----------------------------
# Schemas
# -----------------------------
class ProjectCreate(BaseModel):
    name: str
    customer_name: str
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


# -----------------------------
# Routes
# -----------------------------
@router.post("/projects")
def create_project(payload: ProjectCreate, db: Session = Depends(get_db)):
    project = Project(
        id=generate_id("proj"),
        name=payload.name,
        customer_name=payload.customer_name,
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
            "name": project.name,
            "customer_name": project.customer_name,
            "source_type": project.source_type,
            "source_value": project.source_value,
            "created_at": project.created_at,
        }
    }


@router.get("/projects")
def list_projects(db: Session = Depends(get_db)):
    projects = db.query(Project).order_by(Project.created_at.desc()).all()
    return {
        "projects": [
            {
                "id": p.id,
                "name": p.name,
                "customer_name": p.customer_name,
                "source_type": p.source_type,
                "source_value": p.source_value,
                "created_at": p.created_at,
            }
            for p in projects
        ]
    }


@router.post("/parse-openapi-file")
async def parse_openapi_file(
    project_name: str = Form(...),
    customer_name: str = Form(...),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
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
        name=project_name,
        customer_name=customer_name,
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

    return {
        "message": "OpenAPI parsed and project created successfully",
        "project": {
            "id": project.id,
            "name": project.name,
            "customer_name": project.customer_name,
            "source_type": project.source_type,
            "source_value": project.source_value,
            "created_at": project.created_at,
        },
        "total_endpoints": len(created_endpoints),
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
def list_project_endpoints(project_id: str, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    endpoints = (
        db.query(EndpointInventory)
        .filter(EndpointInventory.project_id == project_id)
        .order_by(EndpointInventory.method, EndpointInventory.path)
        .all()
    )

    return {
        "project_id": project_id,
        "total_endpoints": len(endpoints),
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
):
    endpoint = db.query(EndpointInventory).filter(EndpointInventory.id == endpoint_id).first()
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")

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


@router.post("/projects/{project_id}/decoy-configs")
def create_decoy_config(
    project_id: str,
    payload: DecoyConfigCreate,
    db: Session = Depends(get_db),
):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

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
def list_decoy_configs(project_id: str, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

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
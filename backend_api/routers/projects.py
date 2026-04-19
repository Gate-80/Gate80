from __future__ import annotations

from collections import Counter
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend_api.db.database import get_db
from backend_api.db.models import DecoyConfig, EndpointInventory, Project, ProxyConfig, User
from backend_api.routers.onboarding import generated_proxy_config
from backend_api.routers.user_authentication import require_user


router = APIRouter(prefix="/projects", tags=["projects"])


class ProjectUpdateRequest(BaseModel):
    name: Optional[str] = None
    environment: Optional[str] = None
    onboarding_status: Optional[str] = None


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

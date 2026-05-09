"""
One-time bootstrap: load swagger.json into the demo project's endpoint inventory.

Phase 8 makes the planner read the customer's response schema for every
request. The schema lives in endpoint_inventory in data/gate80_platform.db.
This script populates that table from ./swagger.json directly so we don't
need to go through the full onboarding flow for the demo.

Idempotent — re-running upserts the project row and replaces its endpoints.
"""
from __future__ import annotations

import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend_api.openapi_parser import load_openapi_document, parse_openapi_endpoints
from gate80_platform.db.database import SessionLocal
from gate80_platform.db.models import Project, EndpointInventory

DEMO_PROJECT_ID    = "proj_demo"
DEMO_PROJECT_NAME  = "Digital Wallet (Demo)"
DEMO_CUSTOMER_NAME = "GATE80 Demo Customer"
SWAGGER_PATH       = ROOT / "swagger.json"


def main() -> None:
    if not SWAGGER_PATH.exists():
        print(f"ERROR: {SWAGGER_PATH} not found")
        sys.exit(1)

    print(f"Loading swagger from {SWAGGER_PATH}")
    raw_text = SWAGGER_PATH.read_text()
    spec = load_openapi_document(raw_text)
    endpoints = parse_openapi_endpoints(spec)
    print(f"  parsed {len(endpoints)} endpoints")

    db = SessionLocal()
    try:
        project = db.query(Project).filter(Project.id == DEMO_PROJECT_ID).first()
        if project is None:
            project = Project(
                id=DEMO_PROJECT_ID,
                name=DEMO_PROJECT_NAME,
                customer_name=DEMO_CUSTOMER_NAME,
                source_type="openapi_file",
                source_value=str(SWAGGER_PATH),
                onboarding_status="completed",
                decoy_generation_status="not_started",
            )
            db.add(project)
            db.commit()
            print(f"Created project {DEMO_PROJECT_ID}")
        else:
            print(f"Project {DEMO_PROJECT_ID} already exists")

        deleted = db.query(EndpointInventory).filter(
            EndpointInventory.project_id == DEMO_PROJECT_ID
        ).delete()
        db.commit()
        if deleted:
            print(f"  removed {deleted} stale endpoint rows")

        for ep in endpoints:
            row = EndpointInventory(
                id=f"ep_{uuid.uuid4().hex[:12]}",
                project_id=DEMO_PROJECT_ID,
                path=ep["path"],
                method=ep["method"],
                summary=ep.get("summary"),
                tag=ep.get("tag"),
                requires_auth=ep.get("requires_auth", False),
                request_schema_json=ep.get("request_schema_json"),
                response_schema_json=ep.get("response_schema_json"),
            )
            db.add(row)
        db.commit()
        print(f"Inserted {len(endpoints)} endpoint inventory rows")

        count = db.query(EndpointInventory).filter(
            EndpointInventory.project_id == DEMO_PROJECT_ID
        ).count()
        print(f"  total endpoints in inventory: {count}")

        sample = db.query(EndpointInventory).filter(
            EndpointInventory.project_id == DEMO_PROJECT_ID
        ).limit(3).all()
        print("\n  sample:")
        for r in sample:
            schema_status = "yes" if r.response_schema_json else "no"
            print(f"    {r.method:6s} {r.path}  schema={schema_status}")
    finally:
        db.close()

    print("\nBootstrap complete.")


if __name__ == "__main__":
    main()

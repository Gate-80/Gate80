"""
sync_to_es.py
Reads SQLite logs and indexes them into Elasticsearch.

Run from the project root:
    python3 sync_to_es.py
"""

import json
import sqlite3
import urllib.error
import urllib.request

ES_URL = "http://localhost:9200"
API_LOGS_INDEX = "rasd-api-logs"
PLAN_LOGS_INDEX = "rasd-deception-plans"
DB_PATH = "proxy_logs.db"

GEO_BY_IP = {
    "8.8.8.8": {
        "country_name": "United States",
        "city_name": "Mountain View",
        "location": {"lat": 37.3861, "lon": -122.0839},
    },
    "9.9.9.9": {
        "country_name": "Switzerland",
        "city_name": "Zurich",
        "location": {"lat": 47.3769, "lon": 8.5417},
    },
    "1.1.1.1": {
        "country_name": "Australia",
        "city_name": "Brisbane",
        "location": {"lat": -27.4698, "lon": 153.0251},
    },
    "185.228.168.9": {
        "country_name": "United Kingdom",
        "city_name": "London",
        "location": {"lat": 51.5072, "lon": -0.1276},
    },
}


def _table_exists(conn: sqlite3.Connection, table_name: str) -> bool:
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table_name,),
    ).fetchone()
    return row is not None


def _geo_for_ip(client_ip: str | None) -> dict | None:
    if not client_ip:
        return None
    return GEO_BY_IP.get(client_ip.strip())


def _build_api_log_doc(row: sqlite3.Row) -> dict:
    timestamp = row["timestamp"].replace(" ", "T") if row["timestamp"] else None
    client_ip = row["client_ip"] or "unknown"
    document = {
        "doc_kind": "proxy_request",
        "id": row["id"],
        "request_id": row["request_id"],
        "timestamp": timestamp,
        "@timestamp": timestamp,
        "client_ip": client_ip,
        "method": row["method"],
        "path": row["path"],
        "query_params": row["query_params"],
        "headers": row["headers"],
        "body": row["body"],
        "response_status": row["response_status"],
        "response_time_ms": row["response_time_ms"],
        "forwarded_to_backend": bool(row["forwarded_to_backend"]),
        "backend_error": row["backend_error"],
        "session_id": row["session_id"],
        "anomaly_score": row["anomaly_score"],
        "routed_to": row["routed_to"] or "backend",
        "flagged_as_suspicious": bool(row["flagged_as_suspicious"]),
        "suspicion_reason": row["suspicion_reason"],
        "attack_type": row["attack_type"],
    }
    geo = _geo_for_ip(client_ip)
    if geo:
        document["geo"] = geo
        document["geoip"] = geo
    return document


def _build_plan_log_doc(row: sqlite3.Row) -> dict:
    timestamp = row["timestamp"].replace(" ", "T") if row["timestamp"] else None
    applied_actions = json.loads(row["applied_actions"]) if row["applied_actions"] else []
    rejected_actions = json.loads(row["rejected_actions"]) if row["rejected_actions"] else []
    validated_plan = json.loads(row["validated_plan"]) if row["validated_plan"] else {}
    raw_plan = json.loads(row["raw_plan"]) if row["raw_plan"] else None

    try:
        confidence = float(row["confidence"]) if row["confidence"] is not None else None
    except ValueError:
        confidence = None

    return {
        "doc_kind": "deception_plan",
        "id": row["id"],
        "request_id": row["request_id"],
        "timestamp": timestamp,
        "@timestamp": timestamp,
        "session_id": row["session_id"],
        "attack_type": row["attack_type"],
        "method": row["method"],
        "path": row["path"],
        "plan_id": row["plan_id"],
        "plan_source": row["plan_source"],
        "model_name": row["model_name"],
        "prompt_version": row["prompt_version"],
        "confidence": confidence,
        "rationale": row["rationale"],
        "generation_error": row["generation_error"],
        "response_status_before": row["response_status_before"],
        "response_status_after": row["response_status_after"],
        "validated_plan": validated_plan,
        "raw_plan": raw_plan,
        "applied_actions": applied_actions,
        "rejected_actions": rejected_actions,
        "applied_action_count": len(applied_actions),
        "rejected_action_count": len(rejected_actions),
        "final_body_preview": row["final_body_preview"],
    }


def _append_bulk_record(bulk_lines: list[str], *, index: str, doc_id: str, document: dict) -> None:
    bulk_lines.append(json.dumps({"index": {"_index": index, "_id": doc_id}}))
    bulk_lines.append(json.dumps(document))


def sync() -> None:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    proxy_rows = (
        conn.execute("SELECT * FROM proxy_requests").fetchall()
        if _table_exists(conn, "proxy_requests")
        else []
    )
    plan_rows = (
        conn.execute("SELECT * FROM deception_plan_logs").fetchall()
        if _table_exists(conn, "deception_plan_logs")
        else []
    )
    conn.close()

    print(f"Found {len(proxy_rows)} proxy records in SQLite")
    print(f"Found {len(plan_rows)} deception plans in SQLite")

    if not proxy_rows and not plan_rows:
        print("Nothing to sync.")
        return

    bulk_lines: list[str] = []

    for row in proxy_rows:
        _append_bulk_record(
            bulk_lines,
            index=API_LOGS_INDEX,
            doc_id=str(row["id"]),
            document=_build_api_log_doc(row),
        )

    for row in plan_rows:
        _append_bulk_record(
            bulk_lines,
            index=PLAN_LOGS_INDEX,
            doc_id=f"plan-{row['id']}",
            document=_build_plan_log_doc(row),
        )

    req = urllib.request.Request(
        f"{ES_URL}/_bulk",
        data=("\n".join(bulk_lines) + "\n").encode("utf-8"),
        headers={"Content-Type": "application/x-ndjson"},
        method="POST",
    )

    try:
        res = urllib.request.urlopen(req)
        body = json.loads(res.read())
        if body.get("errors"):
            for item in body["items"]:
                if item.get("index", {}).get("error"):
                    print("Error:", item["index"]["error"])
                    break
        else:
            print(
                "Done! "
                f"{len(proxy_rows)} API records synced to '{API_LOGS_INDEX}', "
                f"{len(plan_rows)} plan records synced to '{PLAN_LOGS_INDEX}'"
            )
    except urllib.error.URLError as exc:
        print(f"Connection failed: {exc}")
        print("Make sure Elasticsearch is running on http://localhost:9200")


if __name__ == "__main__":
    sync()

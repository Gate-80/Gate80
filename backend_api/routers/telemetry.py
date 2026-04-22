from __future__ import annotations

from datetime import datetime
import json
import math
import urllib.error
import urllib.request
from typing import Any

from fastapi import APIRouter, Body

from decoy_api.db.log_models import DecoyRequest, DeceptionPlanLog
from proxy.db.database import SessionLocal as ProxySessionLocal
from proxy.db.models import ProxyRequest


router = APIRouter(prefix="/telemetry", tags=["telemetry"])

ES_URL = "http://127.0.0.1:9200"
DEFAULT_SIZE = 100

KNOWN_GEO_BY_IP = {
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


def _iso_timestamp(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _proxy_doc(row: ProxyRequest) -> dict[str, Any]:
    timestamp = _iso_timestamp(row.timestamp)
    geo = KNOWN_GEO_BY_IP.get((row.client_ip or "").strip())
    return {
        "_id": f"proxy-{row.id}",
        "_source": {
            "@timestamp": timestamp,
            "timestamp": timestamp,
            "doc_kind": "proxy_request",
            "request_id": row.request_id,
            "client_ip": row.client_ip,
            "source_ip": row.client_ip,
            "method": row.method,
            "path": row.path,
            "response_status": row.response_status,
            "status_code": row.response_status,
            "response_time_ms": row.response_time_ms,
            "forwarded_to_backend": bool(row.forwarded_to_backend),
            "session_id": row.session_id,
            "anomaly_score": row.anomaly_score,
            "routed_to": row.routed_to,
            "flagged_as_suspicious": bool(row.flagged_as_suspicious),
            "suspicion_reason": row.suspicion_reason,
            "attack_type": row.attack_type,
            "geo": geo,
            "geoip": geo,
        },
    }


def _decoy_doc(row: DecoyRequest) -> dict[str, Any]:
    timestamp = _iso_timestamp(row.timestamp)
    geo = KNOWN_GEO_BY_IP.get((row.client_ip or "").strip())
    return {
        "_id": f"decoy-{row.id}",
        "_source": {
            "@timestamp": timestamp,
            "timestamp": timestamp,
            "doc_kind": "decoy_request",
            "request_id": row.request_id,
            "client_ip": row.client_ip,
            "source_ip": row.client_ip,
            "method": row.method,
            "path": row.path,
            "response_status": row.response_status,
            "status_code": row.response_status,
            "response_time_ms": row.response_time_ms,
            "session_id": row.session_id,
            "routed_to": "decoy",
            "flagged_as_suspicious": True,
            "attack_type": "deception_engaged",
            "geo": geo,
            "geoip": geo,
        },
    }


def _plan_doc(row: DeceptionPlanLog) -> dict[str, Any]:
    timestamp = _iso_timestamp(row.timestamp)
    return {
        "_id": f"plan-{row.id}",
        "_source": {
            "@timestamp": timestamp,
            "timestamp": timestamp,
            "doc_kind": "deception_plan",
            "request_id": row.request_id,
            "session_id": row.session_id,
            "attack_type": row.attack_type,
            "method": row.method,
            "path": row.path,
            "plan_id": row.plan_id,
            "plan_source": row.plan_source,
            "model_name": row.model_name,
            "confidence": row.confidence,
            "response_status_before": row.response_status_before,
            "response_status_after": row.response_status_after,
            "status_code": row.response_status_after,
            "rationale": row.rationale,
        },
    }


def _all_docs() -> list[dict[str, Any]]:
    proxy_db = ProxySessionLocal()
    try:
        docs = [_proxy_doc(row) for row in proxy_db.query(ProxyRequest).all()]
        docs.extend(_decoy_doc(row) for row in proxy_db.query(DecoyRequest).all())
        docs.extend(_plan_doc(row) for row in proxy_db.query(DeceptionPlanLog).all())
        return docs
    finally:
        proxy_db.close()


def _resolve_field(source: dict[str, Any], field: str) -> Any:
    value: Any = source
    for part in field.split("."):
        if isinstance(value, dict):
            value = value.get(part)
        else:
            return None
    return value


def _normalize_query_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def _match_clause(source: dict[str, Any], clause: dict[str, Any]) -> bool:
    if "match_all" in clause:
        return True

    if "term" in clause:
        for field, expected in clause["term"].items():
            actual = _resolve_field(source, field)
            if isinstance(expected, dict) and "value" in expected:
                expected = expected["value"]
            return actual == expected

    if "terms" in clause:
        for field, expected_values in clause["terms"].items():
            actual = _resolve_field(source, field)
            return actual in expected_values

    if "exists" in clause:
        field = clause["exists"].get("field")
        return _resolve_field(source, field) is not None

    if "range" in clause:
        for field, bounds in clause["range"].items():
            actual = _resolve_field(source, field)
            if actual is None:
                return False
            actual_text = str(actual)
            gte = bounds.get("gte")
            gt = bounds.get("gt")
            lte = bounds.get("lte")
            lt = bounds.get("lt")
            if gte is not None and actual_text < str(gte):
                return False
            if gt is not None and actual_text <= str(gt):
                return False
            if lte is not None and actual_text > str(lte):
                return False
            if lt is not None and actual_text >= str(lt):
                return False
            return True

    if "bool" in clause:
        data = clause["bool"]
        for item in data.get("must", []):
            if not _match_clause(source, item):
                return False
        for item in data.get("filter", []):
            if not _match_clause(source, item):
                return False
        for item in data.get("must_not", []):
            if _match_clause(source, item):
                return False
        should = data.get("should", [])
        if should and not any(_match_clause(source, item) for item in should):
            return False
        return True

    if "query_string" in clause:
        query_text = _normalize_query_text(clause["query_string"].get("query"))
        haystack = json.dumps(source, sort_keys=True).lower()
        return query_text in haystack if query_text else True

    if "multi_match" in clause:
        query_text = _normalize_query_text(clause["multi_match"].get("query"))
        fields = clause["multi_match"].get("fields", [])
        if not query_text:
            return True
        return any(query_text in _normalize_query_text(_resolve_field(source, field)) for field in fields)

    return True


def _apply_query(docs: list[dict[str, Any]], query: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not query:
        return docs
    return [doc for doc in docs if _match_clause(doc["_source"], query)]


def _sort_docs(docs: list[dict[str, Any]], sort_spec: list[Any] | None) -> list[dict[str, Any]]:
    if not sort_spec:
        return sorted(docs, key=lambda doc: doc["_source"].get("@timestamp") or "", reverse=True)

    sorted_docs = docs[:]
    for item in reversed(sort_spec):
        if isinstance(item, str):
            field = item
            order = "asc"
        else:
            field, config = next(iter(item.items()))
            order = (config or {}).get("order", "asc")
        reverse = order == "desc"
        sorted_docs.sort(key=lambda doc: _resolve_field(doc["_source"], field) or "", reverse=reverse)
    return sorted_docs


def _numeric_values(docs: list[dict[str, Any]], field: str) -> list[float]:
    values = []
    for doc in docs:
        value = _resolve_field(doc["_source"], field)
        if value is None:
            continue
        try:
            values.append(float(value))
        except (TypeError, ValueError):
            continue
    return values


def _build_aggs(docs: list[dict[str, Any]], aggs: dict[str, Any] | None) -> dict[str, Any]:
    if not aggs:
        return {}

    result: dict[str, Any] = {}
    for name, config in aggs.items():
        bucket_size = config.get("terms", {}).get("size", 10)

        if "terms" in config:
            field = config["terms"]["field"]
            counts: dict[Any, list[dict[str, Any]]] = {}
            for doc in docs:
                key = _resolve_field(doc["_source"], field)
                if key is None:
                    continue
                counts.setdefault(key, []).append(doc)
            buckets = []
            for key, subset in sorted(counts.items(), key=lambda item: (len(item[1]), str(item[0])), reverse=True)[:bucket_size]:
                bucket = {"key": key, "doc_count": len(subset)}
                nested = _build_aggs(subset, config.get("aggs"))
                if nested:
                    bucket.update(nested)
                buckets.append(bucket)
            result[name] = {"buckets": buckets}
            continue

        if "value_count" in config:
            field = config["value_count"]["field"]
            count = sum(1 for doc in docs if _resolve_field(doc["_source"], field) is not None)
            result[name] = {"value": count}
            continue

        if "avg" in config:
            field = config["avg"]["field"]
            values = _numeric_values(docs, field)
            result[name] = {"value": (sum(values) / len(values)) if values else None}
            continue

        if "min" in config:
            field = config["min"]["field"]
            values = _numeric_values(docs, field)
            result[name] = {"value": min(values) if values else None}
            continue

        if "max" in config:
            field = config["max"]["field"]
            values = _numeric_values(docs, field)
            result[name] = {"value": max(values) if values else None}
            continue

        if "stats" in config:
            field = config["stats"]["field"]
            values = _numeric_values(docs, field)
            count = len(values)
            total = sum(values)
            result[name] = {
                "count": count,
                "min": min(values) if values else None,
                "max": max(values) if values else None,
                "avg": (total / count) if count else None,
                "sum": total,
            }
            continue

        if "filter" in config:
            subset = _apply_query(docs, config["filter"])
            payload = {"doc_count": len(subset)}
            nested = _build_aggs(subset, config.get("aggs"))
            if nested:
                payload.update(nested)
            result[name] = payload
            continue

        if "date_histogram" in config:
            field = config["date_histogram"]["field"]
            interval = config["date_histogram"].get("calendar_interval") or config["date_histogram"].get("fixed_interval") or "day"
            buckets_by_key: dict[str, list[dict[str, Any]]] = {}
            for doc in docs:
                value = _resolve_field(doc["_source"], field)
                if not value:
                    continue
                text = str(value)
                if interval == "hour":
                    key = text[:13] + ":00:00"
                elif interval == "minute":
                    key = text[:16] + ":00"
                else:
                    key = text[:10]
                buckets_by_key.setdefault(key, []).append(doc)
            buckets = []
            for key in sorted(buckets_by_key.keys()):
                subset = buckets_by_key[key]
                bucket = {"key_as_string": key, "doc_count": len(subset)}
                nested = _build_aggs(subset, config.get("aggs"))
                if nested:
                    bucket.update(nested)
                buckets.append(bucket)
            result[name] = {"buckets": buckets}
            continue

        result[name] = {}

    return result


def _fallback_es_search(payload: dict[str, Any]) -> dict[str, Any]:
    docs = _all_docs()
    docs = _apply_query(docs, payload.get("query"))
    docs = _sort_docs(docs, payload.get("sort"))

    offset = int(payload.get("from", 0) or 0)
    size = int(payload.get("size", DEFAULT_SIZE) or DEFAULT_SIZE)
    hits = docs[offset: offset + size]

    return {
        "took": 1,
        "timed_out": False,
        "hits": {
            "total": {"value": len(docs), "relation": "eq"},
            "hits": hits,
        },
        "aggregations": _build_aggs(docs, payload.get("aggs") or payload.get("aggregations")),
    }


def _try_proxy_to_elasticsearch(payload: dict[str, Any]) -> dict[str, Any] | None:
    index = payload.get("index") or payload.get("indices") or payload.get("target")
    if isinstance(index, list):
        index = ",".join(index)
    url = f"{ES_URL}/_search" if not index else f"{ES_URL}/{index}/_search"

    body = payload.get("body") if isinstance(payload.get("body"), dict) else payload
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=2) as response:
            return json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError):
        return None


@router.post("/es-query")
def telemetry_es_query(payload: dict[str, Any] = Body(default_factory=dict)):
    es_response = _try_proxy_to_elasticsearch(payload)
    if es_response is not None:
        return es_response
    return _fallback_es_search(payload)

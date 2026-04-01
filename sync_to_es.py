"""
sync_to_es.py
Reads all records from proxy_logs.db and indexes them into Elasticsearch.

Run from the project root:
    python3 sync_to_es.py
"""

import sqlite3
import json
import urllib.request
import urllib.error

ES_URL   = "http://localhost:9200"
ES_INDEX = "rasd-api-logs"
DB_PATH  = "proxy_logs.db"

def sync():
    # ── Connect to SQLite ──────────────────────────────────────────────────
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM proxy_requests").fetchall()
    conn.close()

    print(f"Found {len(rows)} records in SQLite")

    if not rows:
        print("Nothing to sync.")
        return

    # ── Build NDJSON bulk body ─────────────────────────────────────────────
    bulk = ""
    for r in rows:
        # Action line
        bulk += json.dumps({
            "index": {
                "_index": ES_INDEX,
                "_id":    str(r["id"])
            }
        }) + "\n"

        # Document line — convert row to plain dict safely
        doc = {
            "id":                    r["id"],
            "request_id":            r["request_id"],
            "timestamp":             r["timestamp"].replace(" ", "T") if r["timestamp"] else None,
            "client_ip":             r["client_ip"]             or "unknown",
            "method":                r["method"],
            "path":                  r["path"],
            "query_params":          r["query_params"],
            "headers":               r["headers"],
            "body":                  r["body"],
            "response_status":       r["response_status"],
            "response_time_ms":      r["response_time_ms"],
            "forwarded_to_backend":  bool(r["forwarded_to_backend"]),
            "backend_error":         r["backend_error"],
            "session_id":            r["session_id"],
            "anomaly_score":         r["anomaly_score"],
            "routed_to":             r["routed_to"]             or "backend",
            "flagged_as_suspicious": bool(r["flagged_as_suspicious"]),
            "suspicion_reason":      r["suspicion_reason"],
        }
        bulk += json.dumps(doc) + "\n"

    # ── Send to ES ─────────────────────────────────────────────────────────
    req = urllib.request.Request(
        f"{ES_URL}/_bulk",
        data    = bulk.encode("utf-8"),
        headers = {"Content-Type": "application/x-ndjson"},
        method  = "POST",
    )

    try:
        res  = urllib.request.urlopen(req)
        body = json.loads(res.read())
        if body.get("errors"):
            # Print first error for debugging
            for item in body["items"]:
                if item.get("index", {}).get("error"):
                    print("Error:", item["index"]["error"])
                    break
        else:
            print(f"✅ Done! {len(rows)} records synced to ES index '{ES_INDEX}'")
    except urllib.error.URLError as e:
        print(f"❌ Connection failed: {e}")
        print("Make sure Elasticsearch is running on http://localhost:9200")


if __name__ == "__main__":
    sync()

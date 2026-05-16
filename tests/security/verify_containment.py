#!/usr/bin/env python3
"""
tests/security/verify_containment.py

Standalone Python harness for token-mirroring containment verification.
Snapshots both digital_wallet.db and decoy_wallet.db row counts before and
after a test, then computes the containment ratio.

Usage:
    python verify_containment.py snapshot pre   # take pre-test snapshot
    # ... run attack ...
    python verify_containment.py snapshot post  # take post-test snapshot
    python verify_containment.py diff           # show delta + containment %

Also usable as a library:
    from verify_containment import snapshot, compute_containment
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

# Auto-discover GATE80 root (parent of tests/security/)
SCRIPT_DIR = Path(__file__).resolve().parent
GATE80_ROOT = SCRIPT_DIR.parent.parent
DIGITAL_DB = GATE80_ROOT / "digital_wallet.db"
DECOY_DB   = GATE80_ROOT / "decoy_wallet.db"
PROXY_LOG  = GATE80_ROOT / "proxy_logs.db"

SNAP_DIR = SCRIPT_DIR / "results"
SNAP_DIR.mkdir(exist_ok=True)
PRE_SNAP  = SNAP_DIR / "_verify_pre.json"
POST_SNAP = SNAP_DIR / "_verify_post.json"


def count(db_path: Path, table: str) -> int:
    """Return row count for a table; 0 if table or DB missing."""
    if not db_path.exists():
        return 0
    try:
        with sqlite3.connect(str(db_path)) as c:
            cur = c.execute(f"SELECT COUNT(*) FROM {table}")
            return cur.fetchone()[0]
    except sqlite3.Error:
        return 0


def snapshot() -> dict:
    """Capture row counts in both DBs and proxy log."""
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "digital_wallet": {
            "users":    count(DIGITAL_DB, "users"),
            "wallets":  count(DIGITAL_DB, "wallets"),
            "payments": count(DIGITAL_DB, "payments"),
        },
        "decoy_wallet": {
            "users":    count(DECOY_DB, "users"),
            "wallets":  count(DECOY_DB, "wallets"),
            "payments": count(DECOY_DB, "payments"),
        },
        "proxy_log": {
            "total_requests":         count(PROXY_LOG, "proxy_requests"),
        },
    }


def compute_containment(pre: dict, post: dict) -> dict:
    """Compute deltas and containment percentages."""
    out = {"deltas": {}}
    for dbname in ("digital_wallet", "decoy_wallet"):
        out["deltas"][dbname] = {
            k: post[dbname][k] - pre[dbname][k]
            for k in pre[dbname]
        }

    # Containment percentages per table
    out["containment_pct"] = {}
    for table in ("users", "wallets", "payments"):
        real_delta = out["deltas"]["digital_wallet"][table]
        decoy_delta = out["deltas"]["decoy_wallet"][table]
        total = real_delta + decoy_delta
        if total > 0:
            out["containment_pct"][table] = round(decoy_delta / total * 100, 1)
        elif total == 0:
            out["containment_pct"][table] = None  # no activity
        else:
            out["containment_pct"][table] = None  # rows deleted (?)

    # Verdict
    real_pmt = out["deltas"]["digital_wallet"]["payments"]
    decoy_pmt = out["deltas"]["decoy_wallet"]["payments"]
    real_users = out["deltas"]["digital_wallet"]["users"]
    decoy_users = out["deltas"]["decoy_wallet"]["users"]

    if real_pmt == 0 and real_users == 0 and (decoy_pmt + decoy_users) > 0:
        out["verdict"] = "PERFECT_CONTAINMENT"
    elif (real_pmt + real_users) < (decoy_pmt + decoy_users) / 2:
        out["verdict"] = "STRONG_CONTAINMENT"
    elif decoy_pmt + decoy_users > 0:
        out["verdict"] = "PARTIAL_CONTAINMENT"
    else:
        out["verdict"] = "NO_DECOY_ACTIVITY"

    return out


def cmd_snapshot(which: str) -> None:
    """Take a pre or post snapshot to disk."""
    snap = snapshot()
    target = {"pre": PRE_SNAP, "post": POST_SNAP}.get(which)
    if target is None:
        print(f"ERROR: unknown snapshot type '{which}'. Use 'pre' or 'post'.")
        sys.exit(2)
    target.write_text(json.dumps(snap, indent=2))
    print(f"Snapshot {which} saved: {target}")
    print(json.dumps(snap, indent=2))


def cmd_diff() -> None:
    """Compute and print containment from saved snapshots."""
    if not PRE_SNAP.exists():
        print(f"ERROR: pre-snapshot not found at {PRE_SNAP}")
        sys.exit(2)
    if not POST_SNAP.exists():
        print(f"ERROR: post-snapshot not found at {POST_SNAP}")
        sys.exit(2)

    pre = json.loads(PRE_SNAP.read_text())
    post = json.loads(POST_SNAP.read_text())
    diff = compute_containment(pre, post)

    print("\n=== Containment Analysis ===\n")
    print(f"Pre-snapshot:  {pre['timestamp']}")
    print(f"Post-snapshot: {post['timestamp']}\n")

    print("Real DB (digital_wallet.db) deltas:")
    for k, v in diff["deltas"]["digital_wallet"].items():
        print(f"  {k:12} {v:+d}")

    print("\nDecoy DB (decoy_wallet.db) deltas:")
    for k, v in diff["deltas"]["decoy_wallet"].items():
        print(f"  {k:12} {v:+d}")

    print("\nContainment percentages (decoy / total per table):")
    for k, v in diff["containment_pct"].items():
        if v is None:
            print(f"  {k:12} N/A (no activity)")
        else:
            print(f"  {k:12} {v}%")

    print(f"\nVERDICT: {diff['verdict']}\n")

    # Also save the diff to a JSON file
    out = SNAP_DIR / "_verify_diff.json"
    out.write_text(json.dumps({
        "pre": pre, "post": post, "analysis": diff
    }, indent=2))
    print(f"Full diff saved: {out}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_snap = sub.add_parser("snapshot", help="Take a DB snapshot")
    p_snap.add_argument("which", choices=["pre", "post"])

    sub.add_parser("diff", help="Show containment analysis from snapshots")

    args = parser.parse_args()
    if args.cmd == "snapshot":
        cmd_snapshot(args.which)
    elif args.cmd == "diff":
        cmd_diff()


if __name__ == "__main__":
    main()

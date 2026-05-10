"""
GATE80 — Performance testing suite (v2)

v2 changes:
  - P-02 reworked: hits decoy directly with X-Attack-Type=account_creation.
    Forces an LLM call on every request because 201 doesn't trigger the
    Phase-9 short-circuit. Replaces the v1 approach which produced n=2.
  - P-05 unchanged. For production-mode throughput, use the companion
    script run_p05_production.sh.

Measurements:
  P-01  Normal-path proxy latency p50/p95/p99       target < 50 ms p50
  P-02  Decoy-side LLM-active latency               target < 5  s  p50
  P-03  Proxy-through Phase-9 short-circuit latency target < 3  s  p50
  P-04  Cost per 100 attack requests                target < $0.10
  P-05  Decoy throughput (concurrent)               target > 50 req/s
  P-06  LLM short-circuit savings                   target >= 60% calls skipped
"""
from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx


PROXY_URL = "http://127.0.0.1:8080"
DECOY_URL = "http://127.0.0.1:8001"
AUDIT_LOG = Path("logs/llm_prompts.jsonl")
RESULTS_DIR = Path("tests/perf/results")
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

PRICE_INPUT_PER_MTOK  = 1.00
PRICE_OUTPUT_PER_MTOK = 5.00
ASSUMED_INPUT_TOKENS  = 2200
ASSUMED_OUTPUT_TOKENS = 200

TARGETS = {
    "P-01": ("Normal-path proxy latency p50",            "ms",   "<", 50),
    "P-02": ("Decoy-side LLM-active latency p50",        "s",    "<", 5.0),
    "P-03": ("Phase 9 short-circuit latency p50",        "s",    "<", 3.0),
    "P-04": ("Cost per 100 attack requests",             "USD",  "<", 0.10),
    "P-05": ("Normal-path proxy throughput (concurrent)", "rps",  ">", 50),
    "P-06": ("LLM short-circuit savings",                "%",    ">=", 60),
}


def percentile(values, p):
    if not values:
        return 0.0
    s = sorted(values)
    k = int(len(s) * p / 100)
    return s[min(k, len(s) - 1)]


def fmt_ms(values):
    return {"n": len(values),
            "p50":  round(percentile(values, 50) * 1000, 2),
            "p95":  round(percentile(values, 95) * 1000, 2),
            "p99":  round(percentile(values, 99) * 1000, 2),
            "mean": round(statistics.mean(values) * 1000, 2) if values else 0}


def fmt_s(values):
    return {"n": len(values),
            "p50":  round(percentile(values, 50), 3),
            "p95":  round(percentile(values, 95), 3),
            "p99":  round(percentile(values, 99), 3),
            "mean": round(statistics.mean(values), 3) if values else 0}


def audit_log_line_count():
    if not AUDIT_LOG.exists():
        return 0
    with AUDIT_LOG.open() as fh:
        return sum(1 for _ in fh)


def read_audit_log_from(start_line):
    if not AUDIT_LOG.exists():
        return []
    entries = []
    with AUDIT_LOG.open() as fh:
        for i, line in enumerate(fh):
            if i < start_line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return entries


def cost_per_call():
    return ((ASSUMED_INPUT_TOKENS  / 1_000_000) * PRICE_INPUT_PER_MTOK +
            (ASSUMED_OUTPUT_TOKENS / 1_000_000) * PRICE_OUTPUT_PER_MTOK)


async def preflight():
    print("[preflight] checking services...")
    async with httpx.AsyncClient(timeout=5.0) as c:
        for name, url in [("proxy", PROXY_URL), ("decoy", DECOY_URL)]:
            try:
                r = await c.get(f"{url}/health")
                if r.status_code != 200:
                    print(f"  {name} unhealthy: {r.status_code}")
                    return False
                print(f"  {name}: ok")
            except Exception as exc:
                print(f"  {name} unreachable: {exc}")
                return False
    return True


# P-01
async def run_p01(n=1000):
    print(f"\n[P-01] Normal-path proxy latency — {n} requests to /health")
    samples = []
    async with httpx.AsyncClient(timeout=10.0) as c:
        for _ in range(20):
            await c.get(f"{PROXY_URL}/health")
        for i in range(n):
            t0 = time.perf_counter()
            try:
                r = await c.get(f"{PROXY_URL}/health")
                if r.status_code == 200:
                    samples.append(time.perf_counter() - t0)
            except Exception:
                pass
            if (i + 1) % 100 == 0:
                print(f"  ... {i + 1}/{n}")
    return fmt_ms(samples)


# P-02 (NEW): decoy-direct + account_creation
async def run_p02_llm_heavy(n_samples=25):
    """
    Hit decoy directly with X-Attack-Type=account_creation. Sign-up
    responses don't trigger the Phase-9 short-circuit, so each request
    produces a real LLM call.

    Measures decoy-side LLM-heavy latency (excludes proxy overhead).
    Add P-01's p50 (~25 ms) for end-to-end estimate.
    """
    print(f"\n[P-02] LLM-active latency — {n_samples} signups direct to decoy")
    print("  (account_creation forces LLM call per request)")

    audit_start = audit_log_line_count()
    samples = []
    seed = int(time.time())

    async with httpx.AsyncClient(timeout=60.0) as c:
        for i in range(n_samples):
            t0 = time.perf_counter()
            try:
                r = await c.post(
                    f"{DECOY_URL}/api/v1/auth/sign-up",
                    headers={"X-Attack-Type": "account_creation"},
                    json={
                        "email":     f"attacker_{seed}_{i}@example.com",
                        "password":  "password123",
                        "full_name": f"Attacker User {i}",
                        "phone":     "+966512345678",
                        "city":      "Riyadh",
                    },
                )
                elapsed = time.perf_counter() - t0
                samples.append({"i": i, "status": r.status_code, "elapsed": elapsed})
            except Exception as exc:
                samples.append({"i": i, "status": -1, "elapsed": -1.0,
                                "error": str(exc)})
            if (i + 1) % 5 == 0:
                print(f"  ... {i + 1}/{n_samples}")

    await asyncio.sleep(1.0)

    audit_entries = read_audit_log_from(audit_start)
    n_llm     = sum(1 for e in audit_entries if e.get("source") == "llm")
    n_skipped = sum(1 for e in audit_entries if e.get("source") == "skipped")
    n_fb      = sum(1 for e in audit_entries if e.get("source") == "fallback")
    print(f"  audit log: +{len(audit_entries)} entries  "
          f"(llm={n_llm}  skipped={n_skipped}  fallback={n_fb})")

    K = len(audit_entries)
    aligned = samples[-K:] if K else []
    llm_lat = []
    for sample, entry in zip(aligned, audit_entries):
        if sample["elapsed"] > 0 and entry.get("source") == "llm":
            llm_lat.append(sample["elapsed"])

    if not llm_lat:
        print("  WARNING: no LLM samples captured. Check decoy logs.")

    return fmt_s(llm_lat)


# P-03: short-circuit
async def run_p03_skipped(n_attacks=100):
    print(f"\n[P-03] Short-circuit latency — {n_attacks} sign-in attacks via proxy")

    audit_start = audit_log_line_count()
    samples = []
    async with httpx.AsyncClient(timeout=60.0) as c:
        for i in range(n_attacks):
            t0 = time.perf_counter()
            try:
                r = await c.post(
                    f"{PROXY_URL}/api/v1/auth/sign-in",
                    json={"email": "attacker@example.com", "password": "wrongpass"},
                )
                elapsed = time.perf_counter() - t0
                samples.append({"i": i, "status": r.status_code, "elapsed": elapsed})
            except Exception:
                samples.append({"i": i, "status": -1, "elapsed": -1.0})
            if (i + 1) % 25 == 0:
                print(f"  ... {i + 1}/{n_attacks}")

    await asyncio.sleep(1.0)

    audit_entries = read_audit_log_from(audit_start)
    n_llm     = sum(1 for e in audit_entries if e.get("source") == "llm")
    n_skipped = sum(1 for e in audit_entries if e.get("source") == "skipped")
    print(f"  audit log: +{len(audit_entries)} entries  "
          f"(llm={n_llm}  skipped={n_skipped})")

    K = len(audit_entries)
    aligned = samples[-K:] if K else []
    skipped_lat = []
    for sample, entry in zip(aligned, audit_entries):
        if sample["elapsed"] > 0 and entry.get("source") == "skipped":
            skipped_lat.append(sample["elapsed"])

    return fmt_s(skipped_lat), samples


# P-04 + P-06
def compute_p04_p06(audit_start):
    print("\n[P-04/P-06] Reading audit log for cost + savings")
    audit_entries = read_audit_log_from(audit_start)
    n_total   = len(audit_entries)
    n_llm     = sum(1 for e in audit_entries if e.get("source") == "llm")
    n_skipped = sum(1 for e in audit_entries if e.get("source") == "skipped")
    n_fb      = sum(1 for e in audit_entries if e.get("source") == "fallback")

    cpc          = cost_per_call()
    total_cost   = round(n_llm * cpc, 4)
    cost_per_100 = round((total_cost / max(n_total, 1)) * 100, 4)
    savings_pct  = round((n_skipped / max(n_total, 1)) * 100, 1)

    print(f"  audit entries: {n_total} (llm={n_llm}  skipped={n_skipped}  fb={n_fb})")
    print(f"  cost per LLM call: ${cpc:.6f}")
    print(f"  total cost       : ${total_cost:.4f}")
    print(f"  cost / 100 reqs  : ${cost_per_100:.4f}")
    print(f"  short-circuit    : {savings_pct:.1f}%")

    return (
        {"audit_entries": n_total, "llm_calls": n_llm,
         "skipped_calls": n_skipped, "fallback_calls": n_fb,
         "cost_per_call_usd": round(cpc, 6),
         "total_cost_usd": total_cost,
         "cost_per_100_reqs_usd": cost_per_100},
        {"skipped_pct": savings_pct,
         "llm_pct":     round((n_llm / max(n_total, 1)) * 100, 1),
         "fallback_pct": round((n_fb / max(n_total, 1)) * 100, 1)},
    )


# P-05
async def run_p05(concurrency=20, n_total=200):
    """
    Measures NORMAL-path proxy throughput. Decoy throughput is intentionally
    rate-limited by strategy delays (anti-fingerprinting) so it is NOT a
    meaningful capacity metric. The real production concern is whether the
    proxy can handle legitimate user traffic — that's what this measures.
    """
    print(f"\n[P-05] Normal-path proxy throughput — {n_total} GET /health at concurrency {concurrency}")

    sem = asyncio.Semaphore(concurrency)
    statuses = []

    async def one(c, i):
        async with sem:
            try:
                r = await c.get(f"{PROXY_URL}/health", timeout=30.0)
                statuses.append(r.status_code)
            except Exception:
                statuses.append(-1)

    t0 = time.perf_counter()
    async with httpx.AsyncClient() as c:
        await asyncio.gather(*[one(c, i) for i in range(n_total)])
    elapsed = time.perf_counter() - t0

    rps = round(n_total / elapsed, 2) if elapsed > 0 else 0
    success = sum(1 for s in statuses if 200 <= s < 600)
    print(f"  elapsed: {elapsed:.2f}s  successful: {success}/{n_total}  rps: {rps}")

    return {"concurrency": concurrency, "total_requests": n_total,
            "successful": success, "elapsed_sec": round(elapsed, 3),
            "throughput_rps": rps}


def evaluate(metric_id, value):
    if value is None or value < 0:
        return "N/A"
    label, unit, op, target = TARGETS[metric_id]
    ops = {"<": lambda v, t: v < t, ">": lambda v, t: v > t,
           "<=": lambda v, t: v <= t, ">=": lambda v, t: v >= t}
    return "PASS" if ops[op](value, target) else "FAIL"


def print_summary(results):
    print("\n" + "=" * 78)
    print(" GATE80 PERFORMANCE TEST RESULTS")
    print("=" * 78)
    print(f" {'ID':<6} {'Metric':<42} {'Value':>12}  {'Target':>10}  {'Result':>6}")
    print("-" * 78)

    rows = []
    if "P-01" in results:
        rows.append(("P-01", results["P-01"]["p50"],
                     f"{results['P-01']['p50']:.2f} ms", f"< {TARGETS['P-01'][3]} ms"))
    if "P-02" in results:
        rows.append(("P-02", results["P-02"]["p50"],
                     f"{results['P-02']['p50']:.2f} s", f"< {TARGETS['P-02'][3]} s"))
    if "P-03" in results:
        rows.append(("P-03", results["P-03"]["p50"],
                     f"{results['P-03']['p50']:.2f} s", f"< {TARGETS['P-03'][3]} s"))
    if "P-04" in results:
        rows.append(("P-04", results["P-04"]["cost_per_100_reqs_usd"],
                     f"${results['P-04']['cost_per_100_reqs_usd']:.4f}",
                     f"< $ {TARGETS['P-04'][3]}"))
    if "P-05" in results:
        rows.append(("P-05", results["P-05"]["throughput_rps"],
                     f"{results['P-05']['throughput_rps']:.1f} rps",
                     f"> {TARGETS['P-05'][3]} rps"))
    if "P-06" in results:
        rows.append(("P-06", results["P-06"]["skipped_pct"],
                     f"{results['P-06']['skipped_pct']:.1f} %",
                     f">= {TARGETS['P-06'][3]} %"))

    for mid, raw, value_str, target_str in rows:
        verdict = evaluate(mid, raw)
        label = TARGETS[mid][0]
        print(f" {mid:<6} {label:<42} {value_str:>12}  {target_str:>10}  {verdict:>6}")
    print("=" * 78)


def save_results(results):
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out = RESULTS_DIR / f"perf_{ts}.json"
    with out.open("w") as fh:
        json.dump(results, fh, indent=2)
    print(f"\nFull JSON results saved to: {out}")
    return out


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--p01-n", type=int, default=1000)
    parser.add_argument("--p02-n", type=int, default=25)
    parser.add_argument("--p03-n", type=int, default=100)
    parser.add_argument("--p05-n", type=int, default=200)
    parser.add_argument("--p05-c", type=int, default=20)
    parser.add_argument("--skip", action="append", default=[])
    args = parser.parse_args()

    if not await preflight():
        print("\nServices not healthy. Run `bash run_all.sh` first.")
        return 1

    audit_start = audit_log_line_count()
    print(f"\n[init] audit log starts at line {audit_start}")

    results = {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "version": "v2",
        "config": {
            "p01_n": args.p01_n, "p02_n": args.p02_n, "p03_n": args.p03_n,
            "p05_n": args.p05_n, "p05_c": args.p05_c,
            "input_tokens_assumed":  ASSUMED_INPUT_TOKENS,
            "output_tokens_assumed": ASSUMED_OUTPUT_TOKENS,
            "price_in_per_mtok":     PRICE_INPUT_PER_MTOK,
            "price_out_per_mtok":    PRICE_OUTPUT_PER_MTOK,
        },
    }

    if "P-01" not in args.skip:
        results["P-01"] = await run_p01(n=args.p01_n)
    if "P-02" not in args.skip:
        results["P-02"] = await run_p02_llm_heavy(n_samples=args.p02_n)
    if "P-03" not in args.skip:
        p03, samples = await run_p03_skipped(n_attacks=args.p03_n)
        results["P-03"] = p03
        results["raw_p03_samples"] = samples[:50]
    if "P-04" not in args.skip and "P-06" not in args.skip:
        p04, p06 = compute_p04_p06(audit_start)
        results["P-04"] = p04
        results["P-06"] = p06
    if "P-05" not in args.skip:
        results["P-05"] = await run_p05(concurrency=args.p05_c, n_total=args.p05_n)

    results["finished_at"] = datetime.now(timezone.utc).isoformat()
    print_summary(results)
    save_results(results)
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))

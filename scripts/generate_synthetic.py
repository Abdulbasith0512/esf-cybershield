"""Synthetic event generator: posts demo attack scenarios to the local API.

Scenarios:
  brute-force       6 failed logons, same user, 5-min window -> T1110
  impossible-travel 2 successful logons, same user, different IPs, <60min -> T1078
  port-scan         12 targets from one src_ip in 2 min -> T1046
  priv-esc          single privilege-escalation event -> T1068
  mixed             all of the above + benign background noise

Usage (backend/.venv active, API running):
  python ..\\scripts\\generate_synthetic.py --scenario mixed --api http://localhost:8000
Saves fixtures to data/synthetic/ too.
"""

import argparse
import json
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    import httpx
except ImportError:
    httpx = None

REPO = Path(__file__).resolve().parents[1]
OUT_DIR = REPO / "data" / "synthetic"


def _evt(**kw):
    base = {"event_id": str(uuid.uuid4()), "source": "synthetic", "event_type": "authentication"}
    base.update(kw)
    return base


def benign_noise(now, n=10):
    out = []
    for i in range(n):
        out.append(_evt(timestamp=(now - timedelta(hours=i + 2)).isoformat(),
                        user_id=f"user{(i % 4) + 1}", host=f"ws-{(i % 4) + 1:02d}",
                        src_ip=f"10.0.1.{10 + i}", action="logon", status="success"))
    return out


def scenario_brute_force(now):
    return [_evt(timestamp=(now - timedelta(minutes=4 - i * 0.5)).isoformat(),
                 user_id="victim1", host="ws-01", src_ip="203.0.113.9",
                 action="logon", status="failure") for i in range(6)]


def scenario_impossible_travel(now):
    return [
        _evt(timestamp=(now - timedelta(minutes=50)).isoformat(), user_id="traveler1",
             host="laptop-07", src_ip="198.51.100.23", action="logon", status="success"),
        _evt(timestamp=now.isoformat(), user_id="traveler1",
             host="laptop-07", src_ip="203.0.113.77", action="logon", status="success"),
    ]


def scenario_port_scan(now):
    return [_evt(timestamp=(now - timedelta(seconds=100 - i * 8)).isoformat(),
                 event_type="network", user_id="unknown", host="unknown",
                 src_ip="198.51.100.99", dst_ip=f"10.0.2.{i + 1}", dst_port=20 + i,
                 action="connection", status="success") for i in range(12)]


def scenario_priv_esc(now):
    return [_evt(timestamp=now.isoformat(), event_type="privilege", user_id="victim1",
                 host="ws-01", src_ip="10.0.1.11", action="privilege-escalation", status="success")]


SCENARIOS = {
    "brute-force": scenario_brute_force,
    "impossible-travel": scenario_impossible_travel,
    "port-scan": scenario_port_scan,
    "priv-esc": scenario_priv_esc,
}


def build(scenario, now):
    if scenario == "mixed":
        evts = []
        for name, fn in SCENARIOS.items():
            evts.extend(fn(now))
        evts.extend(benign_noise(now))
        return evts
    if scenario == "benign":
        return benign_noise(now)
    return SCENARIOS[scenario](now)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", default="mixed",
                    choices=["mixed", "benign", *list(SCENARIOS)])
    ap.add_argument("--api", default="http://localhost:8000")
    ap.add_argument("--no-post", action="store_true", help="only write fixture file")
    args = ap.parse_args()

    now = datetime.now(timezone.utc)
    events = build(args.scenario, now)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_file = OUT_DIR / f"{args.scenario}.json"
    out_file.write_text(json.dumps(events, indent=2), encoding="utf-8")
    print(f"wrote {len(events)} events -> {out_file}")

    if args.no_post:
        return
    if httpx is None:
        print("httpx not installed; skipping POST (run with backend .venv)", file=sys.stderr)
        return
    with httpx.Client(base_url=args.api, timeout=30) as client:
        r = client.post("/api/v1/events/bulk", json=events)
        print(f"POST /api/v1/events/bulk -> {r.status_code}")
        try:
            body = r.json()
            print(json.dumps({k: v for k, v in body.items() if k != "results"}, indent=2))
        except Exception:
            print(r.text[:1000])


if __name__ == "__main__":
    main()

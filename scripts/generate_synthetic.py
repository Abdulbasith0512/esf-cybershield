"""Deterministic synthetic SECURITY TELEMETRY generator (Slice 2).

Telemetry only — not attacks. Emits benign enterprise background traffic plus
controlled simulated suspicious sequences. Every record conforms to the Slice 1
``EventCreate`` contract (exact field names, tz-aware timestamps, valid IPs /
ports). Ground truth (scenario_id / scenario_type / synthetic flag) lives ONLY
inside ``raw_event``; top-level columns stay label-free for future ML.

Determinism: ``--seed 42`` always yields the same logical dataset (event_ids
are UUIDv5 over seed/scenario/sequence; timestamps derive from a fixed anchor
plus seeded offsets — never wall-clock).

Usage:
    python scripts/generate_synthetic.py --events 10000 --seed 42 \\
        --output data/synthetic/events.jsonl --format jsonl
    python scripts/generate_synthetic.py --events 500 --seed 7 \\
        --output data/synthetic/sample.csv --format csv \\
        --scenario-mix normal=0.8,brute_force=0.1,credential_compromise=0.1
    python scripts/generate_synthetic.py --events 200 --seed 7 --validate
"""

import argparse
import csv
import io
import json
import random
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

GENERATOR = "esf-cybershield-synthetic-v1"
NAMESPACE = uuid.UUID("9b4e6c2a-1f3d-5b7a-9c8e-2f6a4d1c0e55")
ANCHOR = datetime(2026, 9, 1, 8, 0, 0, tzinfo=timezone.utc)

EVENT_TYPES = [
    "authentication",
    "process_creation",
    "network_connection",
    "dns_query",
    "file_activity",
    "data_transfer",
]
SOURCES = ["windows", "linux", "firewall", "dns", "endpoint"]

# Reserved / documentation ranges only. Never real infrastructure.
SUBNETS = ["10.10.0.0/24", "10.10.20.0/24", "192.168.50.0/24"]
EXTERNAL_IP = "203.0.113.200"  # TEST-NET-3 (RFC 5737)
EXTERNAL_DOMAIN = "update-check.invalid"  # RFC 2606 .invalid
DNS_RESOLVER = "10.10.0.53"

USERS = [f"user_{i:03d}" for i in range(1, 41)]
HOSTS = [f"WIN-{i:03d}" for i in range(1, 25)] + [f"SRV-{i:03d}" for i in range(1, 5)]
SERVICE_ACCOUNTS = ["svc_backup", "svc_reports", "svc_monitor"]

BENIGN_PROCESSES = [
    ("C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\System32\\services.exe", "-k netsvcs"),
    ("C:\\Program Files\\Outlook\\outlook.exe", "C:\\Windows\\explorer.exe", "/recycle"),
    ("C:\\Windows\\System32\\msiexec.exe", "C:\\Windows\\System32\\services.exe", "/i package.msi /quiet"),
    ("/usr/bin/python3", "/usr/bin/systemd", "report.py --daily"),
    ("C:\\Program Files\\Git\\bin\\git.exe", "C:\\Windows\\explorer.exe", "pull --ff-only"),
    ("C:\\Windows\\explorer.exe", "C:\\Windows\\System32\\userinit.exe", None),
]
# Suspicious-looking but BENIGN telemetry text. No exploit syntax, no-encoded
# payloads, no download cradles, no credential-access tokens.
INVENTORY_CMDLINES = [
    "powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\\inventory.ps1",
    "wmic.exe process list brief",
    "systeminfo.exe",
]
BENIGN_DOMAINS = ["intranet.local", "mail.local", "fileserver.local", "updates.local"]
NORMAL_PORTS = [80, 443, 445, 3389, 53, 8080]
MB = 1024 * 1024

DEFAULT_MIX = {
    "normal": 0.88,
    "brute_force": 0.03,
    "suspicious_process": 0.02,
    "unusual_login": 0.02,
    "suspicious_network": 0.02,
    "data_spike": 0.01,
    "credential_compromise": 0.01,
    "benign_volume": 0.01,
}

CSV_COLUMNS = [
    "event_id", "timestamp", "event_type", "source", "host", "user",
    "source_ip", "destination_ip", "destination_port", "protocol",
    "process_name", "parent_process", "command_line", "file_hash",
    "domain", "url", "bytes_sent", "bytes_received", "status", "raw_event",
]


class Ctx:
    """Shared seeded state: rng, seed, monotonic sequence for UUIDv5."""

    def __init__(self, seed: int):
        self.seed = seed
        self.rng = random.Random(seed)
        self.seq = 0

    def event_id(self, scenario_id: str) -> str:
        self.seq += 1
        return str(uuid.uuid5(NAMESPACE, f"{self.seed}/{scenario_id}/{self.seq:06d}"))

    def ip(self, subnet_idx: int | None = None) -> str:
        import ipaddress

        net = ipaddress.ip_network(self.rng.choice(SUBNETS) if subnet_idx is None else SUBNETS[subnet_idx])
        return str(net[self.rng.randint(10, 200)])

    def user(self) -> str:
        return self.rng.choice(USERS)

    def host(self) -> str:
        return self.rng.choice(HOSTS)

    def hex_hash(self) -> str:
        return "".join(self.rng.choice("0123456789abcdef") for _ in range(64))


def _raw(ctx: Ctx, scenario_id: str, scenario_type: str, **meta) -> dict:
    return {
        "generator": GENERATOR,
        "synthetic": True,
        "scenario_id": scenario_id,
        "scenario_type": scenario_type,
        "seed": ctx.seed,
        "source_metadata": meta,
    }


def _base(ctx: Ctx, scenario_id: str, scenario_type: str, ts: datetime,
          event_type: str, source: str, **fields) -> dict:
    evt = {
        "event_id": ctx.event_id(scenario_id),
        "timestamp": ts.isoformat(),
        "event_type": event_type,
        "source": source,
        "host": None,
        "user": None,
        "source_ip": None,
        "destination_ip": None,
        "destination_port": None,
        "protocol": None,
        "process_name": None,
        "parent_process": None,
        "command_line": None,
        "file_hash": None,
        "domain": None,
        "url": None,
        "bytes_sent": None,
        "bytes_received": None,
        "status": None,
        "raw_event": _raw(ctx, scenario_id, scenario_type, telemetry_source=source),
    }
    evt.update({k: v for k, v in fields.items() if v is not None or k in fields})
    return evt


def _business_ts(ctx: Ctx, day: int) -> datetime:
    # Business-hours-weighted timestamp on day offset from anchor.
    hour = ctx.rng.choices(
        population=list(range(24)),
        weights=[1] * 6 + [2] * 2 + [10] * 9 + [4] * 2 + [1] * 5,
        k=1,
    )[0]
    return ANCHOR + timedelta(days=day, hours=hour - 8,
                              minutes=ctx.rng.randint(0, 59),
                              seconds=ctx.rng.randint(0, 59))


# ---------------------------------------------------------------- normal ---

def normal_event(ctx: Ctx, day: int, sid: str) -> dict:
    kind = ctx.rng.choices(
        ["auth", "proc", "dns", "net", "file", "xfer"],
        weights=[30, 20, 20, 12, 8, 10], k=1)[0]
    ts, user, host = _business_ts(ctx, day), ctx.user(), ctx.host()
    if kind == "auth":
        return _base(ctx, sid, "normal", ts, "authentication", ctx.rng.choice(["windows", "linux"]),
                     host=host, user=user, source_ip=ctx.ip(),
                     status="success" if ctx.rng.random() < 0.95 else "failed")
    if kind == "proc":
        proc, parent, cmd = ctx.rng.choice(BENIGN_PROCESSES)
        return _base(ctx, sid, "normal", ts, "process_creation", "endpoint",
                     host=host, user=user, process_name=proc,
                     parent_process=parent, command_line=cmd, status="started")
    if kind == "dns":
        return _base(ctx, sid, "normal", ts, "dns_query", "dns",
                     host=host, user=user, source_ip=ctx.ip(),
                     destination_ip=DNS_RESOLVER, destination_port=53,
                     protocol="UDP", domain=ctx.rng.choice(BENIGN_DOMAINS),
                     status="resolved")
    if kind == "net":
        return _base(ctx, sid, "normal", ts, "network_connection", "firewall",
                     host=host, user=user, source_ip=ctx.ip(),
                     destination_ip=ctx.ip(), destination_port=ctx.rng.choice(NORMAL_PORTS),
                     protocol="TCP", bytes_sent=ctx.rng.randint(1_000, 2_000_000),
                     bytes_received=ctx.rng.randint(1_000, 5_000_000), status="allowed")
    if kind == "file":
        return _base(ctx, sid, "normal", ts, "file_activity", "endpoint",
                     host=host, user=user,
                     process_name=ctx.rng.choice(BENIGN_PROCESSES)[0],
                     file_hash=ctx.hex_hash(), status="created")
    return _base(ctx, sid, "normal", ts, "data_transfer", ctx.rng.choice(["firewall", "endpoint"]),
                 host=host, user=user, source_ip=ctx.ip(), destination_ip=ctx.ip(),
                 destination_port=443, protocol="TCP",
                 bytes_sent=ctx.rng.randint(1 * MB, 150 * MB), status="completed")


# --------------------------------------------------------------- scenarios ---

def scen_brute_force(ctx: Ctx, n: int) -> list[dict]:
    """Multiple failed logons then one success. Telemetry only."""
    out, user, host, ip = [], ctx.user(), ctx.host(), ctx.ip()
    day = ctx.rng.randint(0, 4)
    t0 = ANCHOR + timedelta(days=day, hours=ctx.rng.randint(0, 23))
    sid = f"brute_force_{ctx.seed}_{n:03d}"
    for i in range(4):
        out.append(_base(ctx, sid, "brute_force", t0 + timedelta(seconds=i * 22),
                         "authentication", "windows", host=host, user=user,
                         source_ip=ip, status="failed"))
    out.append(_base(ctx, sid, "brute_force", t0 + timedelta(seconds=4 * 22 + 31),
                     "authentication", "windows", host=host, user=user,
                     source_ip=ip, status="success"))
    return out


def scen_suspicious_process(ctx: Ctx, n: int) -> list[dict]:
    """Login -> parent process -> child process with benign inventory cmdline."""
    user, host, ip = ctx.user(), ctx.host(), ctx.ip()
    t0 = _business_ts(ctx, ctx.rng.randint(0, 4))
    sid = f"suspicious_process_{ctx.seed}_{n:03d}"
    return [
        _base(ctx, sid, "suspicious_process", t0, "authentication", "windows",
              host=host, user=user, source_ip=ip, status="success"),
        _base(ctx, sid, "suspicious_process", t0 + timedelta(seconds=64),
              "process_creation", "endpoint", host=host, user=user,
              process_name="C:\\Windows\\System32\\svchost.exe",
              parent_process="C:\\Windows\\System32\\services.exe",
              command_line="-k netsvcs", status="started"),
        _base(ctx, sid, "suspicious_process", t0 + timedelta(seconds=129),
              "process_creation", "endpoint", host=host, user=user,
              process_name="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
              parent_process="C:\\Windows\\System32\\svchost.exe",
              command_line=ctx.rng.choice(INVENTORY_CMDLINES), status="started"),
        _base(ctx, sid, "suspicious_process", t0 + timedelta(seconds=141),
              "file_activity", "endpoint", host=host, user=user,
              process_name="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
              file_hash=ctx.hex_hash(), status="read"),
    ]


def scen_unusual_login(ctx: Ctx, n: int) -> list[dict]:
    """Same user: daytime baseline over prior days + one 03:xx login."""
    user, host, ip = ctx.user(), ctx.host(), ctx.ip()
    day = ctx.rng.randint(2, 4)
    sid = f"unusual_login_{ctx.seed}_{n:03d}"
    out = [
        _base(ctx, sid, "unusual_login",
              ANCHOR + timedelta(days=day - d, hours=1, minutes=ctx.rng.randint(0, 59)),
              "authentication", "windows", host=host, user=user,
              source_ip=ip, status="success")
        for d in (2, 1)
    ]
    out.append(_base(ctx, sid, "unusual_login",
                     ANCHOR + timedelta(days=day, hours=-5, minutes=ctx.rng.randint(10, 50)),
                     "authentication", "windows", host=host, user=user,
                     source_ip=ip, status="success"))
    return out


def scen_suspicious_network(ctx: Ctx, n: int) -> list[dict]:
    """Login -> connection to documentation-range external host."""
    user, host, ip = ctx.user(), ctx.host(), ctx.ip()
    t0 = _business_ts(ctx, ctx.rng.randint(0, 4))
    sid = f"suspicious_network_{ctx.seed}_{n:03d}"
    return [
        _base(ctx, sid, "suspicious_network", t0, "authentication", "windows",
              host=host, user=user, source_ip=ip, status="success"),
        _base(ctx, sid, "suspicious_network", t0 + timedelta(seconds=47),
              "dns_query", "dns", host=host, user=user, source_ip=ip,
              destination_ip=DNS_RESOLVER, destination_port=53, protocol="UDP",
              domain=EXTERNAL_DOMAIN, status="resolved"),
        _base(ctx, sid, "suspicious_network", t0 + timedelta(seconds=53),
              "network_connection", "firewall", host=host, user=user,
              source_ip=ip, destination_ip=EXTERNAL_IP, destination_port=4443,
              protocol="TCP", bytes_sent=ctx.rng.randint(1_000, 50_000),
              bytes_received=ctx.rng.randint(1_000, 50_000), status="allowed"),
    ]


def scen_data_spike(ctx: Ctx, n: int) -> list[dict]:
    """Normal 50-110 MB transfers then one ~4 GB transfer. Telemetry only."""
    user, host, ip = ctx.user(), ctx.host(), ctx.ip()
    day = ctx.rng.randint(1, 4)
    sid = f"data_spike_{ctx.seed}_{n:03d}"
    out = [
        _base(ctx, sid, "data_spike",
              ANCHOR + timedelta(days=day - 1, hours=i * 2 - 8),
              "data_transfer", "firewall", host=host, user=user, source_ip=ip,
              destination_ip=ctx.ip(), destination_port=443, protocol="TCP",
              bytes_sent=ctx.rng.randint(50 * MB, 110 * MB), status="completed")
        for i in range(5)
    ]
    out.append(_base(ctx, sid, "data_spike",
                     ANCHOR + timedelta(days=day, hours=2),
                     "data_transfer", "firewall", host=host, user=user,
                     source_ip=ip, destination_ip=EXTERNAL_IP,
                     destination_port=443, protocol="TCP",
                     bytes_sent=4 * 1024 * MB, status="completed"))
    return out


def scen_credential_compromise(ctx: Ctx, n: int, fixed_id: str | None = None) -> list[dict]:
    """PRIMARY DEMO: fails -> success -> process -> shell telemetry ->
    external connection -> large transfer. All benign telemetry text."""
    user, host, ip = ctx.user(), ctx.host(), ctx.ip()
    t0 = ANCHOR + timedelta(days=ctx.rng.randint(1, 4), hours=1,
                            minutes=ctx.rng.randint(0, 59), seconds=2)
    sid = fixed_id or f"credential_compromise_{ctx.seed}_{n:03d}"
    events = [
        _base(ctx, sid, "credential_compromise", t0 + timedelta(seconds=i * 8),
              "authentication", "windows", host=host, user=user,
              source_ip=ip, status="failed")
        for i in range(3)
    ]
    events.append(_base(ctx, sid, "credential_compromise", t0 + timedelta(seconds=52),
                        "authentication", "windows", host=host, user=user,
                        source_ip=ip, status="success"))
    events.append(_base(ctx, sid, "credential_compromise", t0 + timedelta(minutes=2, seconds=8),
                        "process_creation", "endpoint", host=host, user=user,
                        process_name="C:\\Windows\\System32\\svchost.exe",
                        parent_process="C:\\Windows\\System32\\services.exe",
                        command_line="-k netsvcs", status="started"))
    events.append(_base(ctx, sid, "credential_compromise", t0 + timedelta(minutes=2, seconds=13),
                        "process_creation", "endpoint", host=host, user=user,
                        process_name="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                        parent_process="C:\\Windows\\System32\\svchost.exe",
                        command_line=INVENTORY_CMDLINES[0], status="started"))
    events.append(_base(ctx, sid, "credential_compromise", t0 + timedelta(minutes=3),
                        "network_connection", "firewall", host=host, user=user,
                        source_ip=ip, destination_ip=EXTERNAL_IP,
                        destination_port=443, protocol="TCP",
                        bytes_sent=12_000, bytes_received=30_000, status="allowed"))
    events.append(_base(ctx, sid, "credential_compromise", t0 + timedelta(minutes=4, seconds=29),
                        "data_transfer", "firewall", host=host, user=user,
                        source_ip=ip, destination_ip=EXTERNAL_IP,
                        destination_port=443, protocol="TCP",
                        bytes_sent=4 * 1024 * MB, status="completed"))
    return events


def scen_benign_volume(ctx: Ctx, n: int) -> list[dict]:
    """Legitimate high-volume service workload (negative example)."""
    svc, host = ctx.rng.choice(SERVICE_ACCOUNTS), f"SRV-{ctx.rng.randint(1, 4):03d}"
    t0 = _business_ts(ctx, ctx.rng.randint(0, 4))
    sid = f"benign_volume_{ctx.seed}_{n:03d}"
    out = []
    for i in range(12):
        ts = t0 + timedelta(minutes=i * 5)
        if i % 3 == 0:
            out.append(_base(ctx, sid, "benign_volume", ts, "authentication",
                             "linux", host=host, user=svc, source_ip=ctx.ip(),
                             status="success"))
        else:
            out.append(_base(ctx, sid, "benign_volume", ts, "data_transfer",
                             "endpoint", host=host, user=svc, source_ip=ctx.ip(),
                             destination_ip=ctx.ip(), destination_port=443,
                             protocol="TCP",
                             bytes_sent=ctx.rng.randint(50 * MB, 300 * MB),
                             status="completed"))
    return out


SCENARIO_BUILDERS = {
    "brute_force": scen_brute_force,
    "suspicious_process": scen_suspicious_process,
    "unusual_login": scen_unusual_login,
    "suspicious_network": scen_suspicious_network,
    "data_spike": scen_data_spike,
    "credential_compromise": scen_credential_compromise,
    "benign_volume": scen_benign_volume,
}

CHAIN_SIZES = {
    "brute_force": 5, "suspicious_process": 4, "unusual_login": 3,
    "suspicious_network": 3, "data_spike": 6, "credential_compromise": 8,
    "benign_volume": 12,
}


def parse_mix(spec: str | None) -> dict[str, float]:
    if not spec:
        return dict(DEFAULT_MIX)
    mix: dict[str, float] = {}
    for part in spec.split(","):
        key, _, val = part.partition("=")
        key, val = key.strip(), val.strip()
        if key not in DEFAULT_MIX:
            raise ValueError(f"unknown scenario in --scenario-mix: {key!r}")
        mix[key] = float(val)
    if abs(sum(mix.values()) - 1.0) > 0.02:
        raise ValueError("--scenario-mix weights must sum to ~1.0")
    return mix


def generate(seed: int, total: int, mix: dict[str, float]) -> list[dict]:
    """Build exactly `total` deterministic events. Suspicious chains first
    (always including one credential_compromise_001 demo when N >= 50),
    normal background fills the remainder; result sorted by timestamp with a
    seeded fraction delivered out of order."""
    ctx = Ctx(seed)
    events: list[dict] = []
    counters = {k: 0 for k in SCENARIO_BUILDERS}

    def add_chain(kind: str, **kw):
        counters[kind] += 1
        events.extend(SCENARIO_BUILDERS[kind](ctx, counters[kind], **kw))

    # Primary demo always present for meaningful dataset sizes.
    budget = {k: int(total * w) for k, w in mix.items() if k != "normal"}
    if total >= 50 and budget.get("credential_compromise", 0) < CHAIN_SIZES["credential_compromise"]:
        budget["credential_compromise"] = CHAIN_SIZES["credential_compromise"]
    if total >= 50:
        add_chain("credential_compromise", fixed_id="credential_compromise_001")
        budget["credential_compromise"] -= CHAIN_SIZES["credential_compromise"]
    for kind, size in CHAIN_SIZES.items():
        if kind == "credential_compromise":
            continue
        n_chains = max(budget.get(kind, 0) // size, 0)
        for _ in range(n_chains):
            add_chain(kind)

    events.sort(key=lambda e: e["timestamp"])
    # Fill remainder with normal background (dominates the dataset).
    day = 0
    while len(events) < total:
        sid = f"normal_{ctx.seed}_{day // 40:02d}"
        events.append(normal_event(ctx, day % 5, sid))
        day += 1
    events = events[:total]
    events.sort(key=lambda e: e["timestamp"])
    # Seeded out-of-order delivery on a small fraction.
    swaps = max(1, total // 100)
    for _ in range(swaps):
        i = ctx.rng.randint(0, len(events) - 2)
        events[i], events[i + 1] = events[i + 1], events[i]
    return events


def write_jsonl(events: list[dict], path: Path) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")


def write_csv(events: list[dict], path: Path) -> None:
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        w.writeheader()
        for e in events:
            row = dict(e)
            row["raw_event"] = json.dumps(e["raw_event"])
            w.writerow(row)


def validate_against_contract(events: list[dict]) -> list[str]:
    """Parse every record with the real EventCreate. Returns error strings."""
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
    from app.schemas.events import EventCreate

    errors = []
    for i, e in enumerate(events):
        try:
            EventCreate(**e)
        except Exception as exc:  # noqa: BLE001 -- report, don't raise
            errors.append(f"record {i} ({e.get('event_id')}): {exc}")
    return errors


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Deterministic synthetic SECURITY TELEMETRY generator. "
                    "Telemetry only — no malware, exploits, or attack tooling. "
                    "Output conforms to the Slice 1 EventCreate contract.",
    )
    ap.add_argument("--events", type=int, default=10000, help="total events to generate")
    ap.add_argument("--seed", type=int, default=42, help="deterministic seed (same seed = same dataset)")
    ap.add_argument("--output", default="data/synthetic/events.jsonl", help="output file path")
    ap.add_argument("--format", choices=["jsonl", "csv"], default="jsonl", help="output format")
    ap.add_argument("--scenario-mix", default=None,
                    help="comma weights, e.g. normal=0.8,brute_force=0.1,credential_compromise=0.1 (sum ~1.0)")
    ap.add_argument("--validate", action="store_true",
                    help="validate every record against EventCreate after generation")
    args = ap.parse_args()

    if args.events < 1:
        ap.error("--events must be >= 1")
    mix = parse_mix(args.scenario_mix)
    events = generate(args.seed, args.events, mix)

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    if args.format == "csv":
        write_csv(events, out)
    else:
        write_jsonl(events, out)

    from collections import Counter

    dist = Counter(e["raw_event"]["scenario_type"] for e in events)
    print(f"wrote {len(events)} events (seed={args.seed}) -> {out}")
    for k, v in sorted(dist.items()):
        print(f"  {k}: {v} ({v / len(events):.1%})")

    if args.validate:
        errors = validate_against_contract(events)
        if errors:
            print(f"CONTRACT VALIDATION FAILED: {len(errors)} errors", file=sys.stderr)
            for e in errors[:10]:
                print(f"  {e}", file=sys.stderr)
            sys.exit(1)
        print(f"contract validation ok: {len(events)} records pass EventCreate")


if __name__ == "__main__":
    main()

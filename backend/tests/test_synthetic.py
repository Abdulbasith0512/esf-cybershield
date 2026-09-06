"""Slice 2 tests: generator determinism, contract, scenarios, formats.

No DB, no API, no ML deps. The generator module is loaded from scripts/.
"""

import csv
import importlib.util
import json
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"


def load_generator():
    spec = importlib.util.spec_from_file_location(
        "generate_synthetic", SCRIPTS / "generate_synthetic.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["generate_synthetic"] = mod
    spec.loader.exec_module(mod)
    return mod


gen = load_generator()
BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))
from app.schemas.events import EventCreate  # noqa: E402


def test_deterministic_same_seed():
    a = gen.generate(42, 300, gen.DEFAULT_MIX)
    b = gen.generate(42, 300, gen.DEFAULT_MIX)
    assert a == b


def test_different_seed_differs():
    a = gen.generate(42, 300, gen.DEFAULT_MIX)
    b = gen.generate(43, 300, gen.DEFAULT_MIX)
    assert a != b


def test_event_ids_unique():
    evts = gen.generate(42, 1000, gen.DEFAULT_MIX)
    ids = [e["event_id"] for e in evts]
    assert len(set(ids)) == len(ids)


def test_required_fields_exist():
    for e in gen.generate(7, 200, gen.DEFAULT_MIX):
        for f in ("event_id", "timestamp", "event_type", "source", "raw_event"):
            assert e.get(f), f"missing {f}"


def test_scenario_metadata_exists():
    for e in gen.generate(7, 200, gen.DEFAULT_MIX):
        raw = e["raw_event"]
        assert raw.get("scenario_id") and raw.get("scenario_type")
        assert raw.get("generator") == gen.GENERATOR
        assert raw.get("synthetic") is True


def test_all_scenarios_generable():
    ctx = gen.Ctx(1)
    assert len(gen.scen_brute_force(ctx, 1)) == 5
    assert len(gen.scen_suspicious_process(ctx, 1)) == 4
    assert len(gen.scen_unusual_login(ctx, 1)) == 3
    assert len(gen.scen_suspicious_network(ctx, 1)) == 3
    assert len(gen.scen_data_spike(ctx, 1)) == 6
    assert len(gen.scen_credential_compromise(ctx, 1)) == 8
    assert len(gen.scen_benign_volume(ctx, 1)) == 12


def test_multistage_ordering():
    evts = gen.generate(42, 2000, gen.DEFAULT_MIX)
    chain = sorted(
        (e for e in evts if e["raw_event"]["scenario_id"] == "credential_compromise_001"),
        key=lambda e: e["timestamp"])
    assert len(chain) == 8
    assert [e["timestamp"] for e in chain] == sorted(e["timestamp"] for e in chain)
    assert [e["event_type"] for e in chain] == [
        "authentication", "authentication", "authentication", "authentication",
        "process_creation", "process_creation", "network_connection", "data_transfer"]
    assert [e["status"] for e in chain[:4]] == ["failed"] * 3 + ["success"]


def test_normal_and_suspicious_present():
    evts = gen.generate(42, 2000, gen.DEFAULT_MIX)
    types = {e["raw_event"]["scenario_type"] for e in evts}
    assert "normal" in types
    assert "credential_compromise" in types
    normal_share = sum(1 for e in evts if e["raw_event"]["scenario_type"] == "normal") / len(evts)
    assert normal_share > 0.5  # normal dominates


@pytest.fixture()
def scratch_dir():
    # NOTE: pytest's tmp_path is unusable on machines where
    # %TEMP%\pytest-of-<user> is owned by another principal; use a fresh
    # mkdtemp directory instead (same semantics, no fixed dirname).
    d = Path(tempfile.mkdtemp(prefix="esf-synth-"))
    try:
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_jsonl_valid(scratch_dir):
    evts = gen.generate(42, 100, gen.DEFAULT_MIX)
    p = scratch_dir / "t.jsonl"
    gen.write_jsonl(evts, p)
    rows = [json.loads(line) for line in p.read_text().splitlines()]
    assert len(rows) == 100 and rows[0]["event_id"] == evts[0]["event_id"]


def test_csv_valid(scratch_dir):
    evts = gen.generate(42, 100, gen.DEFAULT_MIX)
    p = scratch_dir / "t.csv"
    gen.write_csv(evts, p)
    with open(p, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 100
    assert json.loads(rows[0]["raw_event"])["scenario_id"] == evts[0]["raw_event"]["scenario_id"]


def test_pass_api_schema():
    for e in gen.generate(42, 500, gen.DEFAULT_MIX):
        EventCreate(**e)


def test_no_ground_truth_top_level():
    for e in gen.generate(42, 200, gen.DEFAULT_MIX):
        assert "scenario_id" not in e and "scenario_type" not in e and "synthetic" not in e


def test_command_lines_benign():
    blob = json.dumps(gen.generate(42, 2000, gen.DEFAULT_MIX)).lower()
    for token in ("mimikatz", "sekurlsa", "invoke-mimikatz", "meterpreter",
                  "cobalt strike", "frombase64string", "-enc ", "-encodedcommand",
                  "downloadstring", "iex(", "certutil -urlcache", "bitsadmin"):
        assert token not in blob, f"banned token {token!r} in telemetry"


def test_primary_ip_mapping_stable_unique_private():
    import ipaddress

    ctx = gen.Ctx(42)
    ips = [ctx.primary_ip(u) for u in gen.USERS + gen.SERVICE_ACCOUNTS]
    assert len(set(ips)) == len(ips)  # no accidental sharing
    assert ctx.primary_ip("user_001") == gen.Ctx(42).primary_ip("user_001")
    for ip in ips:
        assert ipaddress.ip_address(ip).is_private


def test_normal_users_stable_source_ip():
    evts = gen.generate(42, 2000, gen.DEFAULT_MIX)
    per_user: dict[str, set] = {}
    for e in evts:
        if e["raw_event"]["scenario_type"] == "normal" and e["event_type"] == "authentication":
            per_user.setdefault(e["user"], set()).add(e["source_ip"])
    assert len(per_user) > 10
    assert all(len(v) == 1 for v in per_user.values()), "normal auth must use the primary IP"


def test_benign_volume_stable_ip():
    ctx = gen.Ctx(9)
    chain = gen.scen_benign_volume(ctx, 1)
    auth = [e for e in chain if e["event_type"] == "authentication"]
    assert len({e["source_ip"] for e in auth}) == 1
    assert auth[0]["source_ip"] == ctx.primary_ip(auth[0]["user"])


def test_brute_force_consistent_attacker_ip():
    ctx = gen.Ctx(9)
    chain = gen.scen_brute_force(ctx, 1)
    ips = {e["source_ip"] for e in chain}
    assert len(ips) == 1
    (ip,) = ips
    assert ip != ctx.primary_ip(chain[0]["user"])


def test_cred_comp_controlled_new_ip():
    ctx = gen.Ctx(9)
    chain = gen.scen_credential_compromise(ctx, 1, fixed_id="credential_compromise_001")
    auth = [e for e in chain if e["event_type"] == "authentication"]
    assert len({e["source_ip"] for e in auth}) == 1  # coherent single attacker IP
    assert auth[0]["source_ip"] != ctx.primary_ip(auth[0]["user"])


def test_unusual_login_new_ip():
    ctx = gen.Ctx(9)
    chain = gen.scen_unusual_login(ctx, 1)
    base = {e["source_ip"] for e in chain[:-1]}
    assert len(base) == 1  # baseline shares the primary IP
    assert chain[-1]["source_ip"] not in base  # night login is the new IP

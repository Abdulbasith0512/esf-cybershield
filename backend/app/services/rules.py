"""YAML-driven rule engine. Each rule queries recent normalized history."""

from datetime import timedelta
from pathlib import Path

import yaml
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models.normalized_event import NormalizedEvent
from app.db.models.signals import Detection

RULES_DIR = Path(__file__).parent.parent / "detections" / "rules"


def load_rules() -> list[dict]:
    rules = []
    for path in sorted(RULES_DIR.glob("*.yml")):
        with open(path, encoding="utf-8") as f:
            rules.append(yaml.safe_load(f))
    return rules


def _add_detection(db: Session, event: NormalizedEvent, rule: dict, detail: dict) -> Detection:
    det = Detection(
        normalized_event_id=event.id,
        rule_id=rule["rule_id"],
        rule_name=rule.get("rule_name", rule["rule_id"]),
        severity=rule.get("severity", "medium"),
        mitre_technique=rule.get("mitre_technique"),
        detail=detail,
    )
    db.add(det)
    return det


def run_rules(db: Session, event: NormalizedEvent) -> list[Detection]:
    """Evaluate all rules against `event` + recent history. Caller flushes/commits."""
    hits: list[Detection] = []
    for rule in load_rules():
        rid = rule["rule_id"]
        params = rule.get("params", {})
        if rid == "brute-force-5-fail-5min":
            hits.extend(_check_brute_force(db, event, rule, params))
        elif rid == "impossible-travel":
            hits.extend(_check_impossible_travel(db, event, rule, params))
        elif rid == "port-scan-10-dst-2min":
            hits.extend(_check_port_scan(db, event, rule, params))
        elif rid == "priv-escalation":
            hits.extend(_check_priv_esc(db, event, rule, params))
    return hits


def _check_brute_force(db, event, rule, params) -> list:
    if event.status != params.get("status", "failure"):
        return []
    if event.user_id in ("unknown", ""):
        return []
    window = timedelta(minutes=params.get("window_minutes", 5))
    since = event.ts - window
    count = db.execute(
        select(func.count())
        .select_from(NormalizedEvent)
        .where(
            NormalizedEvent.user_id == event.user_id,
            NormalizedEvent.status == "failure",
            NormalizedEvent.ts >= since,
            NormalizedEvent.ts <= event.ts,
        )
    ).scalar_one()
    if count >= params.get("threshold", 5):
        return [_add_detection(db, event, rule, {"fail_count": count, "window_minutes": params.get("window_minutes", 5)})]
    return []


def _check_impossible_travel(db, event, rule, params) -> list:
    if event.status != params.get("status", "success") or not event.src_ip:
        return []
    if event.user_id in ("unknown", ""):
        return []
    window = timedelta(minutes=params.get("window_minutes", 60))
    since = event.ts - window
    prior_ips = db.execute(
        select(NormalizedEvent.src_ip)
        .where(
            NormalizedEvent.user_id == event.user_id,
            NormalizedEvent.status == "success",
            NormalizedEvent.ts >= since,
            NormalizedEvent.ts < event.ts,
            NormalizedEvent.src_ip.is_not(None),
        )
        .distinct()
    ).scalars().all()
    if prior_ips and event.src_ip not in set(prior_ips):
        return [_add_detection(db, event, rule, {"prior_ips": prior_ips[-5:], "current_ip": event.src_ip})]
    return []


def _check_port_scan(db, event, rule, params) -> list:
    if not event.src_ip:
        return []
    window = timedelta(minutes=params.get("window_minutes", 2))
    since = event.ts - window
    rows = db.execute(
        select(NormalizedEvent.dst_ip, NormalizedEvent.dst_port).where(
            NormalizedEvent.src_ip == event.src_ip,
            NormalizedEvent.ts >= since,
            NormalizedEvent.ts <= event.ts,
        )
    ).all()
    distinct_targets = {(r[0], r[1]) for r in rows}
    if len(distinct_targets) >= params.get("threshold", 10):
        return [_add_detection(db, event, rule, {"distinct_targets": len(distinct_targets)})]
    return []


def _check_priv_esc(db, event, rule, params) -> list:
    actions = [a.lower() for a in params.get("actions", [])]
    haystack = f"{event.action} {event.event_type}".lower()
    if any(a in haystack for a in actions):
        return [_add_detection(db, event, rule, {"action": event.action, "event_type": event.event_type})]
    return []

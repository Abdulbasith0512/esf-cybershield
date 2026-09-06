"""Transparent incident risk scorer. Deterministic arithmetic over detections +
mappings. Distinct-rule / unique-event / distinct-tactic math throughout:
repeats add context, never linear multiples. Not a probability of compromise.
"""

from app.services.correlate.models import Incident
from app.services.detect.models import DetectionResult
from app.services.mitre.config import RiskConfig
from app.services.mitre.models import MitreMapping, RiskBand, RiskBreakdown


def _band(score: int, config: RiskConfig) -> RiskBand:
    for upper, band in config.bands:
        if score <= upper:
            return band
    return "CRITICAL"


def score_risk(incident: Incident, detections_by_id: dict[str, DetectionResult],
               mappings: list[MitreMapping] | None = None,
               config: RiskConfig | None = None) -> tuple[int, RiskBreakdown, str]:
    """Return (risk_score 0-100, breakdown, explanation). Inputs never mutated."""
    config = config or RiskConfig()
    dets = [detections_by_id[i] for i in incident.detection_ids if i in detections_by_id]
    rules = {d.rule_id for d in dets}
    mappings = mappings if mappings is not None else []

    severity_points = config.sev_base.get(incident.severity, 0)
    diversity_points = min(len(rules) * config.diversity_per_rule, config.diversity_cap)
    mean_conf = (sum(d.confidence or 0 for d in dets) / len(dets)) if dets else 0.0
    confidence_points = int(round(10 * mean_conf))
    evidence_points = min(len(set(incident.evidence_event_ids)), config.evidence_cap)

    has_ioc = any((d.metadata or {}).get("matched_ioc") for d in dets)
    has_proc = any(d.rule_id in ("PROC-001", "PROC-002") for d in dets)
    contextual_points = (config.ioc_points if has_ioc else 0) \
        + (config.process_points if has_proc else 0)

    transfer_points = 0
    for d in dets:
        if d.rule_id == "DATA-001":
            sent = (d.metadata or {}).get("bytes_sent") or 0
            thresh = (d.metadata or {}).get("threshold") or 1
            doublings, ratio = 0, sent / max(thresh, 1)
            while ratio >= 2:
                doublings += 1
                ratio /= 2
            transfer_points = max(transfer_points,
                                  min(config.transfer_min + config.transfer_step * doublings,
                                      config.transfer_max))
    seq = {frozenset(p) for p in (incident.metadata or {}).get("sequence_hits", [])}
    flat = {r for pair in seq for r in pair}
    has3 = {"AUTH-001", "PROC-001", "NET-001"} <= flat or \
        {"AUTH-001", "PROC-002", "NET-001"} <= flat
    has4 = has3 and "DATA-001" in flat
    sequence_points = config.chain4_points if has4 else (config.chain3_points if has3 else 0)

    tactics = {m.tactic for m in mappings}
    mitre_points = min(len(tactics) * config.mitre_per_tactic, config.mitre_cap)

    total = severity_points + diversity_points + confidence_points + evidence_points \
        + contextual_points + transfer_points + sequence_points + mitre_points
    total = max(0, min(100, int(total)))
    breakdown = RiskBreakdown(
        severity_points=severity_points, diversity_points=diversity_points,
        confidence_points=confidence_points, evidence_points=evidence_points,
        sequence_points=sequence_points, mitre_points=mitre_points,
        contextual_points=contextual_points + transfer_points, total=total)
    return total, breakdown, explain(incident, dets, mappings, breakdown, _band(total, config))


def explain(incident: Incident, dets: list, mappings: list[MitreMapping],
            breakdown: RiskBreakdown, band: str) -> str:
    bits = [f"base severity {incident.severity} ({breakdown.severity_points})",
            f"{len({d.rule_id for d in dets})} distinct detection rules "
            f"({breakdown.diversity_points})"]
    if any((d.metadata or {}).get("matched_ioc") for d in dets):
        bits.append("IOC evidence present")
    if any(d.rule_id in ("PROC-001", "PROC-002") for d in dets):
        bits.append("suspicious process activity present")
    data = [d for d in dets if d.rule_id == "DATA-001"]
    if data:
        biggest = max((d.metadata or {}).get("bytes_sent", 0) for d in data)
        bits.append(f"large outbound transfer ({biggest:,} bytes)")
    if breakdown.sequence_points:
        bits.append("recognized multi-stage sequence")
    if mappings:
        tids = sorted({m.technique_id for m in mappings})
        bits.append(f"ATT&CK hypotheses {', '.join(tids)}")
    return (f"Risk {breakdown.total} ({band}) is elevated because the incident contains "
            + ", ".join(bits) + ". Score prioritizes investigation; it is not a "
            "probability of compromise.")

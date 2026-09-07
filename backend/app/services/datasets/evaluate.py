"""Post-hoc evaluation of flow detections against dataset labels.

Boundary: labels are read here, AFTER detection, for reporting only. Nothing
in this module feeds labels into detectors, fingerprints, thresholds, or
features. Detector inputs remain label-free telemetry.
"""

import hashlib
import json
import random
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

BENIGN_LABEL = "Benign"


def normalize_label(raw: Any) -> str:
    """Trim harmless formatting; map documented benign spellings to Benign.

    Every other value passes through verbatim and is reported as observed.
    """
    text = raw.strip() if isinstance(raw, str) else ""
    if text.lower() == "benign":
        return BENIGN_LABEL
    return text


def label_by_event(events: list[dict]) -> dict[str, str]:
    """Map event_id -> normalized label, read post-hoc from evaluation metadata."""
    out = {}
    for event in events:
        raw_event = event.get("raw_event") or {}
        evaluation = raw_event.get("evaluation_only") or {}
        out[event["event_id"]] = normalize_label(evaluation.get("label", ""))
    return out


def attribute(detections: list, labels: dict[str, str]) -> dict[str, dict[str, list[str]]]:
    """Attribute covered events per detection.

    A detection covers exactly its evidence_event_ids. Mixed-label evidence
    is split deterministically: each covered event keeps its own label.
    """
    result = {}
    for det in detections:
        covered = sorted(set(det.evidence_event_ids) & set(labels))
        result[det.detection_id] = {
            "rule_id": det.rule_id,
            "covered": covered,
            "positive": sorted(e for e in covered if labels[e] not in (BENIGN_LABEL, "")),
            "benign": sorted(e for e in covered if labels[e] in (BENIGN_LABEL, "")),
        }
    return result


def prf(tp: int, fp: int, fn: int, tn: int) -> dict[str, float | None]:
    """Precision/recall/F1/FPR. None where the denominator is undefined."""
    precision = tp / (tp + fp) if (tp + fp) > 0 else None
    recall = tp / (tp + fn) if (tp + fn) > 0 else None
    if precision is None or recall is None or (precision + recall) == 0:
        f1 = None
    else:
        f1 = 2 * precision * recall / (precision + recall)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else None
    return {"precision": precision, "recall": recall, "f1": f1, "fpr": fpr}


def _counts_from(covered: set[str], labels: dict[str, str],
                   support_positive: int, universe_size: int) -> dict:
    covered = set(covered)
    tp = sum(1 for e in covered if labels.get(e, BENIGN_LABEL) not in (BENIGN_LABEL, ""))
    fp = len(covered) - tp
    fn = support_positive - tp
    tn = universe_size - len(covered) - fn
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn}


def rule_metrics(detections: list, labels: dict[str, str],
                 support_positive: int | None = None,
                 universe_size: int | None = None) -> dict[str, dict]:
    """Per-rule metrics over event-level attribution. Deterministic output order.

    Optional count overrides support streaming evaluation, where the full
    label map is unavailable but totals are known: support_positive defaults
    to the positives in `labels`, universe_size to `len(labels)`.
    """
    by_rule: dict[str, list] = {}
    for det in detections:
        by_rule.setdefault(det.rule_id, []).append(det)
    universe = set(labels)
    positive = {e for e, lab in labels.items() if lab not in (BENIGN_LABEL, "")}
    if support_positive is None:
        support_positive = len(positive)
    if universe_size is None:
        universe_size = len(universe)
    out = {}
    for rule_id in sorted(by_rule):
        covered: set[str] = set()
        for det in by_rule[rule_id]:
            covered.update(det.evidence_event_ids)
        covered &= universe
        counts = _counts_from(covered, labels, support_positive, universe_size)
        out[rule_id] = {
            "detections": len(by_rule[rule_id]),
            "covered_events": len(covered),
            **counts,
            **prf(counts["tp"], counts["fp"], counts["fn"], counts["tn"]),
            "support_positive": support_positive,
            "support_benign": universe_size - support_positive,
        }
    return out


def overall_summary(detections: list, labels: dict[str, str],
                    support_positive: int | None = None,
                    universe_size: int | None = None) -> dict:
    """Unique-event coverage across rules. No averaged F1 (misleading)."""
    covered: set[str] = set()
    for det in detections:
        covered.update(det.evidence_event_ids)
    covered &= set(labels)
    universe = set(labels)
    positive = {e for e, lab in labels.items() if lab not in (BENIGN_LABEL, "")}
    if support_positive is None:
        support_positive = len(positive)
    if universe_size is None:
        universe_size = len(universe)
    counts = _counts_from(covered, labels, support_positive, universe_size)
    return {
        "total_detections": len(detections),
        "covered_events": len(covered),
        **counts,
        **prf(counts["tp"], counts["fp"], counts["fn"], counts["tn"]),
        "support_positive": support_positive,
        "support_benign": universe_size - support_positive,
    }


def coverage_from_labels(detections: list, labels: dict[str, str],
                         totals: dict[str, int]) -> dict[str, dict]:
    """Detector x dataset-label breakdown from a label map + totals.

    Streaming-friendly twin of label_coverage (which derives both from an
    in-memory event list). Labels read as observed, verbatim.
    """
    by_label: dict[str, set[str]] = {}
    for det in detections:
        for eid in det.evidence_event_ids:
            if eid in labels:
                by_label.setdefault(labels[eid], set()).add(eid)
    out = {}
    for label in sorted(totals):
        total = totals[label]
        hit = len(by_label.get(label, set()))
        out[label] = {"events": total, "covered": hit,
                      "coverage": (hit / total) if total else None}
    return out


def label_coverage(detections: list, events: list[dict]) -> dict[str, dict]:
    """Detector x dataset-label breakdown. Labels read as observed, verbatim."""
    labels = label_by_event(events)
    totals: Counter[str] = Counter(labels.values())
    return coverage_from_labels(detections, labels, dict(totals))


def reservoir_sample(rows: list, count: int, sample_seed: int) -> list:
    """Deterministic label-blind sampling. Order-independent of input order."""
    rng = random.Random(sample_seed)
    indexed = sorted(enumerate(rows), key=lambda pair: pair[0])
    chosen = set(rng.sample([i for i, _ in indexed], min(count, len(indexed))))
    return [row for i, row in indexed if i in chosen]


def stratified_sample(labeled: list[tuple], count: int, sample_seed: int) -> list:
    """Label-stratified sampling. EVALUATION-ONLY diagnostic: labels select
    rows here, so any result using it must be reported as diagnostic, never
    as detector behavior on natural traffic."""
    rng = random.Random(sample_seed)
    groups: dict[str, list] = {}
    for item in labeled:
        groups.setdefault(item[0], []).append(item[1])
    per_label = max(1, count // max(1, len(groups)))
    out = []
    for label in sorted(groups):
        members = groups[label]
        out.extend(rng.sample(members, min(per_label, len(members))))
    return out


def parse_ts(value: Any) -> datetime | None:
    try:
        text = str(value).replace("Z", "+00:00")
        moment = datetime.fromisoformat(text)
    except (ValueError, TypeError):
        return None
    if moment.tzinfo is None:
        return None
    return moment


def chunked_detect(adapter, path: Path, source_file: str, config,
                   chunk_rows: int, overlap_minutes: int,
                   limit: int | None = None) -> list:
    """Stream a large CSV in bounded row blocks with temporal overlap carry.

    Each block is adapted, merged with prior events younger than
    (block_max - overlap), and fed to detect_flows; detections union by
    fingerprint. FLOW-005 (session catalog) is excluded here and handled by
    session_rule_sample on a bounded stride sample instead.
    """
    from app.services.detect.flow import detect_flows

    overlap = timedelta(minutes=overlap_minutes)
    carry: list[dict] = []
    seen: dict[str, object] = {}
    adapted_total = 0
    block: list[dict] = []

    def flush(current: list[dict]) -> None:
        for det in detect_flows(current, config=config):
            if det.rule_id == "FLOW-005":
                continue
            seen.setdefault(det.fingerprint, det)

    for _, raw in adapter.iter_rows(path, limit=limit):
        result = adapter.normalize_row(raw, source_file=source_file,
                                       source_row=adapted_total + 1)
        adapted_total += 1
        if not result.ok or result.event is None:
            continue
        block.append(result.event)
        if len(block) >= chunk_rows:
            window = block + [e for e in carry if _fresh(e, block, overlap)]
            flush(window)
            carry = _carry_events(block, carry, overlap)
            block = []
    if block:
        flush(block + [e for e in carry if _fresh(e, block, overlap)])
    return sorted(seen.values(), key=lambda d: d.fingerprint)


def session_rule_sample(adapter, path: Path, source_file: str, cap: int,
                        limit: int | None = None) -> list[dict]:
    """Deterministic stride sample for the session-scoped FLOW-005 rule.

    Reads row count first (streaming), then keeps every k-th adapted event up
    to cap, preserving temporal order. Used only when the full set does not
    fit the bounded path; reported as such.
    """
    total = 0
    for _ in adapter.iter_rows(path, limit=limit):
        total += 1
    if total == 0:
        return []
    keep = min(total, cap)
    step = total / keep
    wanted = {int(i * step) for i in range(keep)}
    out = []
    for n, raw in adapter.iter_rows(path, limit=limit):
        if (n - 1) in wanted:
            result = adapter.normalize_row(raw, source_file=source_file, source_row=n)
            if result.ok and result.event is not None:
                out.append(result.event)
    return out


def collect_evidence_labels(adapter, path: Path, source_file: str,
                            wanted: set[str],
                            limit: int | None = None
                            ) -> tuple[dict[str, str], dict[str, int], int]:
    """Second streaming pass: label totals plus labels for wanted event IDs.

    Memory stays bounded: only counters plus the (small) wanted set are kept.
    Returns (labels_by_id, totals_by_label, rejected_count).
    """
    labels_by_id: dict[str, str] = {}
    totals: Counter[str] = Counter()
    remaining = set(wanted)
    rejected = 0
    for n, raw in adapter.iter_rows(path, limit=limit):
        result = adapter.normalize_row(raw, source_file=source_file, source_row=n)
        if not result.ok or result.event is None:
            rejected += 1
            continue
        event = result.event
        label = normalize_label(
            (event.get("raw_event") or {}).get("evaluation_only", {}).get("label", ""))
        totals[label or "<empty>"] += 1
        if event["event_id"] in remaining:
            labels_by_id[event["event_id"]] = label
            remaining.discard(event["event_id"])
    return labels_by_id, dict(totals), rejected


def _fresh(event: dict, block: list[dict], overlap: timedelta) -> bool:
    moments = [parse_ts(e.get("timestamp")) for e in block]
    moments = [m for m in moments if m is not None]
    if not moments:
        return False
    edge = max(moments) - overlap
    moment = parse_ts(event.get("timestamp"))
    return moment is not None and moment > edge


def _carry_events(block: list[dict], carry: list[dict], overlap: timedelta) -> list[dict]:
    moments = [parse_ts(e.get("timestamp")) for e in block]
    moments = [m for m in moments if m is not None]
    if not moments:
        return carry
    edge = max(moments) - overlap
    kept = [e for e in block + carry if (parse_ts(e.get("timestamp")) or edge) > edge]
    by_id = {e["event_id"]: e for e in kept}
    return sorted(by_id.values(), key=lambda e: (str(e.get("timestamp")), e["event_id"]))


def stride_sample(events: list[dict], cap: int) -> list[dict]:
    """Deterministic stride sample preserving temporal order. Used only for
    the session-scoped FLOW-005 rule under chunked evaluation."""
    if len(events) <= cap:
        return list(events)
    step = len(events) / cap
    return [events[int(i * step)] for i in range(cap)]


def run_id_for(files: list[str], params: dict) -> str:
    """Deterministic run identifier from inputs (not wall-clock)."""
    payload = json.dumps({"files": sorted(files), "params": params}, sort_keys=True)
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()[:12]


def build_summary(run_id: str, files: list[str], params: dict, stats: dict,
                  per_rule: dict, overall: dict, coverage: dict,
                  fp_notes: list[dict], leakage_ok: bool) -> dict:
    return {
        "run_id": run_id,
        "files": sorted(files),
        "params": params,
        "stats": stats,
        "per_rule": per_rule,
        "overall": overall,
        "label_coverage": coverage,
        "false_positives": fp_notes,
        "leakage_check": "pass" if leakage_ok else "fail",
    }


def render_markdown(summary: dict) -> str:
    """Human-readable report. Machine-readable form is summary.json."""
    lines = [
        "# CSE-CIC-IDS2018 Flow Detection Evaluation",
        "",
        f"run_id: `{summary['run_id']}`",
        f"files: {', '.join(summary['files'])}",
        f"params: `{json.dumps(summary['params'], sort_keys=True)}`",
        "",
        "## Totals",
        "",
        f"- rows processed: {summary['stats'].get('rows', '?')}",
        f"- adapted events: {summary['stats'].get('events', '?')}",
        f"- detections: {summary['stats'].get('detections', '?')}",
        "",
        "## Per-rule metrics",
        "",
        "| rule | detections | covered | TP | FP | FN | precision | recall | F1 | FPR |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for rule_id, metrics in sorted(summary["per_rule"].items()):
        def show(value):
            if value is None:
                return "n/a"
            return f"{value:.3f}" if isinstance(value, float) else str(value)

        lines.append(
            f"| {rule_id} | {metrics['detections']} | {metrics['covered_events']} | "
            f"{metrics['tp']} | {metrics['fp']} | {metrics['fn']} | "
            f"{show(metrics['precision'])} | {show(metrics['recall'])} | "
            f"{show(metrics['f1'])} | {show(metrics['fpr'])} |")
    lines += [
        "",
        "## Label coverage (post-hoc, evaluation only)",
        "",
    ]
    for label, cov in sorted(summary["label_coverage"].items()):
        pct = f"{100.0 * cov['covered'] / cov['events']:.1f}%" if cov["events"] else "n/a"
        lines.append(f"- {label}: {cov['covered']}/{cov['events']} ({pct})")
    lines += [
        "",
        "## Notes",
        "",
        "- Labels were read AFTER detection for reporting only.",
        "- Benchmark numbers measure lab behavior, not production efficacy.",
        "",
    ]
    return "\n".join(lines) + "\n"

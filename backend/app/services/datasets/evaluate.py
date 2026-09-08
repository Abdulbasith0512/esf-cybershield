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

import csv as _csv_module

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


EMPTY_LABEL = "<empty>"
NON_ATTACK_LABELS = frozenset({BENIGN_LABEL, "", EMPTY_LABEL})


def attack_labels_from_totals(totals: dict[str, int]) -> list[str]:
    """Sorted distinct non-benign labels observed in the evaluated stream."""
    return sorted(lab for lab, count in totals.items()
                  if lab not in NON_ATTACK_LABELS and count > 0)


def build_attack_episodes(label_map: dict[str, str]) -> dict[str, set[str]]:
    """Post-hoc attack episodes: one per distinct normalized non-benign label.

    Must be called only after detection has finished; labels never flow into
    detectors or bucket construction. Episode membership is the full set of
    labelled event IDs, never reconstructed from capped evidence.
    """
    episodes: dict[str, set[str]] = {}
    for event_id, label in label_map.items():
        if label not in NON_ATTACK_LABELS:
            episodes.setdefault(label, set()).add(event_id)
    return episodes


def _bucket_hit_labels(bucket_ids: list[str],
                       label_lookup: dict[str, str]) -> set[str] | None:
    """Attack labels intersected by one detection bucket, or None when the
    bucket is unevaluable (empty membership, or no member has a known label).

    Unknown member IDs are ignored. An evaluable all-benign bucket returns an
    empty set (bucket FP), never None. Empty membership is unavailable, never
    a false positive.
    """
    if not bucket_ids:
        return None
    known = {label_lookup[eid] for eid in set(bucket_ids) if eid in label_lookup}
    if not known:
        return None
    return {lab for lab in known if lab not in NON_ATTACK_LABELS}


def _bucket_status(evaluated: int, unavailable: int) -> tuple[str, str]:
    if unavailable == 0:
        return "available", ""
    if evaluated == 0:
        return "unavailable", "no detection carries bucket_event_ids"
    return ("partial",
            f"{unavailable} detection(s) carry no bucket_event_ids and are excluded")


def bucket_metrics(detections: list, bucket_labels: dict[str, str],
                   attack_labels) -> dict:
    """Global bucket-hit metrics. Zero-denominator policy: precision is None
    with no evaluable buckets; recall is None with no attack episodes."""
    attack_set = set(attack_labels)
    tp = fp = evaluated = unavailable = 0
    hit: set[str] = set()
    for det in detections:
        result = _bucket_hit_labels(det.bucket_event_ids, bucket_labels)
        if result is None:
            unavailable += 1
            continue
        evaluated += 1
        if result:
            tp += 1
            hit.update(result)
        else:
            fp += 1
    status, reason = _bucket_status(evaluated, unavailable)
    hit_in_scope = hit & attack_set
    return {
        "detection_bucket_count": len(detections),
        "evaluated_buckets": evaluated,
        "unavailable_buckets": unavailable,
        "bucket_tp": tp,
        "bucket_fp": fp,
        "bucket_precision": tp / (tp + fp) if evaluated else None,
        "attack_bucket_count": len(attack_set),
        "attack_bucket_hit": len(hit_in_scope),
        "bucket_recall": (len(hit_in_scope) / len(attack_set)) if attack_set else None,
        "bucket_metric_status": status,
        "bucket_metric_reason": reason,
    }


def per_rule_bucket_metrics(detections: list, bucket_labels: dict[str, str],
                            attack_labels) -> dict[str, dict]:
    """Per-rule bucket-hit metrics. The attack-episode denominator is the same
    global episode set for every rule; each rule reports the episodes its own
    detections hit. Rules with no detections are absent."""
    attack_set = set(attack_labels)
    by_rule: dict[str, list] = {}
    for det in detections:
        by_rule.setdefault(det.rule_id, []).append(det)
    out = {}
    for rule_id in sorted(by_rule):
        out[rule_id] = bucket_metrics(by_rule[rule_id], bucket_labels, attack_set)
    return out


def _iso_stamp(value: Any) -> str:
    moment = value.isoformat() if hasattr(value, "isoformat") else str(value)
    return moment


def detection_record(det, network_key=None) -> dict:
    """Deterministic replay record for one DetectionResult. Labels never read."""
    return {
        "detection_id": det.detection_id,
        "fingerprint": det.fingerprint,
        "rule_id": det.rule_id,
        "rule_name": det.rule_name,
        "severity": det.severity,
        "confidence": det.confidence,
        "reason": det.reason,
        "first_seen": _iso_stamp(det.first_seen),
        "last_seen": _iso_stamp(det.last_seen),
        "evidence_event_ids": sorted(det.evidence_event_ids),
        "bucket_event_ids": sorted(set(det.bucket_event_ids)),
        "network_entity": list(network_key) if network_key is not None else None,
        "metadata": json.loads(json.dumps(det.metadata or {}, sort_keys=True, default=str)),
    }


def incident_record(incident, det_by_id: dict | None = None) -> dict:
    """Deterministic replay record for one Incident. Member buckets resolved
    from caller-provided detections; missing members contribute nothing."""
    det_by_id = det_by_id or {}
    bucket_union: set[str] = set()
    for did in incident.detection_ids:
        det = det_by_id.get(did)
        if det is not None:
            bucket_union.update(det.bucket_event_ids)
    return {
        "incident_id": incident.incident_id,
        "fingerprint": incident.fingerprint,
        "title": incident.title,
        "severity": incident.severity,
        "status": incident.status,
        "confidence": incident.confidence,
        "reason": incident.reason,
        "detection_ids": sorted(incident.detection_ids),
        "evidence_event_ids": sorted(set(incident.evidence_event_ids)),
        "bucket_event_ids": sorted(bucket_union),
        "first_seen": _iso_stamp(incident.first_seen),
        "last_seen": _iso_stamp(incident.last_seen),
        "metadata": json.loads(json.dumps(incident.metadata or {}, sort_keys=True, default=str)),
    }


def write_jsonl(records: list[dict], path) -> str:
    """Write deterministic JSONL (fingerprint order, sorted keys). Returns sha256."""
    ordered = sorted(records, key=lambda r: r.get("fingerprint", ""))
    digest = hashlib.sha256()
    with Path(path).open("w", encoding="utf-8", newline="\n") as handle:
        for record in ordered:
            line = json.dumps(record, sort_keys=True, default=str) + "\n"
            digest.update(line.encode("utf-8"))
            handle.write(line)
    return digest.hexdigest()


def _median_number(values: list) -> float | None:
    ordered = sorted(values)
    count = len(ordered)
    if count == 0:
        return None
    mid = count // 2
    if count % 2:
        return float(ordered[mid])
    return (ordered[mid - 1] + ordered[mid]) / 2.0


def incident_metrics(incidents: list, det_by_id: dict,
                     bucket_labels: dict[str, str], attack_labels) -> dict:
    """Incident-level post-hoc metrics. Hit = member bucket union (falling back
    to member evidence only when no member carries bucket IDs) intersects an
    attack episode. No incident FPR: benign episodes are not a partition, so a
    conventional false-positive denominator would mislead; it is omitted."""
    attack_set = set(attack_labels)
    hit_episodes: set[str] = set()
    attack_hit = 0
    with_buckets = 0
    with_network = 0
    sizes: list[int] = []
    compositions: Counter[str] = Counter()
    for incident in incidents:
        sizes.append(len(incident.detection_ids))
        members = [det_by_id[did] for did in incident.detection_ids if did in det_by_id]
        bucket_union = {eid for det in members for eid in det.bucket_event_ids}
        if bucket_union:
            with_buckets += 1
            pool = bucket_union
        else:
            pool = {eid for det in members for eid in det.evidence_event_ids}
        labels_hit = {bucket_labels[eid] for eid in pool if eid in bucket_labels}
        attack_hit_labels = {lab for lab in labels_hit if lab not in NON_ATTACK_LABELS}
        if attack_hit_labels:
            attack_hit += 1
            hit_episodes.update(lab for lab in attack_hit_labels if lab in attack_set)
        rule_ids = sorted({det.rule_id for det in members}) or \
            sorted((incident.metadata or {}).get("rule_ids", []))
        compositions["+".join(rule_ids) if rule_ids else "<unknown>"] += 1
        network_entities = (incident.metadata or {}).get("network_entities")
        if network_entities:
            with_network += 1
    total = len(incidents)
    in_scope = len(hit_episodes & attack_set)
    return {
        "total_incidents": total,
        "attack_incidents": attack_hit,
        "incident_attack_hit": attack_hit,
        "benign_incidents": total - attack_hit,
        "incident_precision": attack_hit / total if total else None,
        "attack_bucket_count": len(attack_set),
        "attack_bucket_hit": in_scope,
        "incident_recall": (in_scope / len(attack_set)) if attack_set else None,
        "detections_per_incident": (sum(sizes) / total) if total else None,
        "median_detections_per_incident": _median_number(sizes),
        "max_detections_per_incident": max(sizes) if sizes else None,
        "rule_composition": dict(sorted(compositions.items())),
        "incidents_with_evidence": sum(1 for i in incidents if i.evidence_event_ids),
        "incidents_with_buckets": with_buckets,
        "incidents_with_network": with_network,
    }


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


def build_time_index(adapter, path: Path, source_file: str,
                     limit: int | None = None) -> tuple[list[tuple[float, int, int]], int]:
    """Single streaming pass building a compact (epoch, source_row, offset) index.

    Byte offsets address data-line starts so rows can be retrieved in any
    order later without re-scanning per row. Only compact triples are kept —
    never normalized events. Rejected rows are counted, never raised.
    """
    resolved = Path(path)
    index: list[tuple[float, int, int]] = []
    rejected = 0
    header = read_header_fields(resolved)
    with resolved.open("rb") as handle:
        handle.readline()  # header consumed once; offsets address data lines
        emitted = 0
        while True:
            if limit is not None and emitted >= limit:
                break
            offset = handle.tell()
            line = handle.readline()
            if not line:
                break
            if next(_csv_module.reader([line.decode("utf-8")]), None) == []:
                continue  # blank line: DictReader skips these without consuming a row number
            emitted += 1
            source_row = emitted
            values = next(_csv_module.reader([line.decode("utf-8")]))
            row: dict[str, str] = {}
            for pos, key in enumerate(header):
                row[key] = values[pos] if pos < len(values) else ""
            result = adapter.normalize_row(row, source_file=source_file,
                                           source_row=source_row)
            if not result.ok or result.event is None:
                rejected += 1
                continue
            moment = parse_ts(result.event.get("timestamp"))
            if moment is None:
                rejected += 1
                continue
            index.append((moment.timestamp(), source_row, offset))
    return index, rejected


def read_header_fields(path: Path) -> list[str]:
    """Header field names verbatim, matching the adapter's input contract."""
    with Path(path).open("rb") as handle:
        first = handle.readline()
        if not first:
            from app.services.datasets.base import AdapterError

            raise AdapterError(f"CSV has no header row: {path}")
        return next(_csv_module.reader([first.decode("utf-8-sig")]))


def chunked_detect(adapter, path: Path, source_file: str, config,
                   chunk_rows: int, overlap_minutes: int,
                   limit: int | None = None, order: str = "file") -> list:
    """Stream a large CSV in bounded row blocks with temporal overlap carry.

    Each block is adapted, merged with prior events younger than
    (block_max - overlap), and fed to detect_flows; detections union by
    fingerprint. FLOW-005 (session catalog) is excluded here and handled by
    session_rule_sample on a bounded stride sample instead.

    order="file" preserves the legacy row-order path exactly. order="time"
    builds a timestamp index first and processes time-contiguous chunks, so
    the overlap carry stays bounded on physically unordered input.
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

    def flush_block(block: list[dict], carry: list[dict]) -> list[dict]:
        edge = block_edge(block, overlap)
        window = block + [e for e in carry
                          if _is_fresh(parse_ts(e.get("timestamp")), edge)]
        flush(window)
        return _carry_events(block, carry, overlap)

    if order == "time":
        return _chunked_detect_time_ordered(
            adapter, path, source_file, config, chunk_rows, overlap,
            limit, flush, seen)

    for _, raw in adapter.iter_rows(path, limit=limit):
        result = adapter.normalize_row(raw, source_file=source_file,
                                       source_row=adapted_total + 1)
        adapted_total += 1
        if not result.ok or result.event is None:
            continue
        block.append(result.event)
        if len(block) >= chunk_rows:
            carry = flush_block(block, carry)
            block = []
    if block:
        carry = flush_block(block, carry)
    return sorted(seen.values(), key=lambda d: d.fingerprint)


def _chunked_detect_time_ordered(adapter, path: Path, source_file: str, config,
                                 chunk_rows: int, overlap: timedelta,
                                 limit: int | None, flush, seen: dict) -> list:
    """Time-ordered chunked detection over a timestamp index.

    The index is partitioned into consecutive time-contiguous groups of at
    most chunk_rows rows; each group is retrieved via byte offsets (single
    file handle, offset-sorted reads), adapted, merged with the overlap
    carry, and flushed. Carry stays bounded because each group spans a
    narrow time range. Deterministic: index order is (epoch, source_row).
    """
    from app.services.detect.flow import detect_flows

    resolved = Path(path)
    index, _ = build_time_index(adapter, resolved, source_file, limit)
    ordered = sorted(index, key=lambda e: (e[0], e[1]))
    header = read_header_fields(resolved)
    carry: list[dict] = []
    with resolved.open("rb") as handle:
        handle.readline()  # header consumed once; offsets address data lines
        pos = 0
        total = len(ordered)
        while pos < total:
            group = ordered[pos:pos + chunk_rows]
            pos += len(group)
            block = _read_group(handle, header, group, adapter, source_file)
            if not block:
                continue
            edge = block_edge(block, overlap)
            window = block + [e for e in carry
                              if _is_fresh(parse_ts(e.get("timestamp")), edge)]
            for det in detect_flows(window, config=config):
                if det.rule_id == "FLOW-005":
                    continue
                seen.setdefault(det.fingerprint, det)
            carry = _carry_events(block, carry, overlap)
    return sorted(seen.values(), key=lambda d: d.fingerprint)


def _read_group(handle, header: list[str], group: list, adapter,
                source_file: str) -> list[dict]:
    """Adapt one time-contiguous index group. Reads members in file-offset
    order (near-sequential I/O), then orders events by (epoch, source_row)
    matching the index. Malformed lines are skipped, never raised."""
    members = sorted(group, key=lambda e: e[2])
    ordered: list[tuple[float, int, dict]] = []
    for _, source_row, offset in members:
        handle.seek(offset)
        line = handle.readline()
        if not line or not line.strip():
            continue
        values = next(_csv_module.reader([line.decode("utf-8")]))
        row: dict[str, str] = {}
        for pos, key in enumerate(header):
            row[key] = values[pos] if pos < len(values) else ""
        result = adapter.normalize_row(row, source_file=source_file,
                                       source_row=source_row)
        if result.ok and result.event is not None:
            moment = parse_ts(result.event.get("timestamp"))
            epoch = moment.timestamp() if moment is not None else float("inf")
            ordered.append((epoch, source_row, result.event))
    ordered.sort(key=lambda t: (t[0], t[1]))
    return [event for _, _, event in ordered]


def evaluate_flow005_full(adapter, path: Path, source_file: str, config,
                          limit: int | None = None,
                          max_pairs: int = 100000) -> tuple[list, dict]:
    """Exact streaming evaluation of the session-scoped FLOW-005 rule.

    Replicates ProtocolPortNovelty semantics without holding all events:
    pass 0 finds the time span, pass 1 builds the first-third catalog and
    buffers (count + earliest-5, by timestamp then event_id) per novel pair.
    Bucket membership is retained as compact (moment, event_id) pairs only.
    Detections are built with make_result using the rule's own identity,
    confidence, reason template, and metadata keys. A cross-validation test
    locks equivalence with rule.evaluate on fixture data.
    """
    from app.services.detect.flow.rules import ProtocolPortNovelty
    from app.services.detect.models import make_result

    rule = ProtocolPortNovelty(config)
    info: dict = {"mode": "full-catalog", "overflow_pairs": False,
                  "catalog_pairs": 0}
    tmin = tmax = None
    for n, raw in adapter.iter_rows(path, limit=limit):
        result = adapter.normalize_row(raw, source_file=source_file, source_row=n)
        if not result.ok or result.event is None:
            continue
        moment = parse_ts(result.event.get("timestamp"))
        if moment is None:
            continue
        if tmin is None or moment < tmin:
            tmin = moment
        if tmax is None or moment > tmax:
            tmax = moment
    if tmin is None:
        return [], info
    # Naive-UTC stamps matching engine.prepare, so make_result sees _ts.
    from app.services.detect.common import coerce_ts

    split = tmin + (tmax - tmin) / 3
    catalog: set[tuple] = set()
    counts: dict[tuple, int] = {}
    earliest: dict[tuple, list] = {}
    bucket_ids: dict[tuple, list] = {}
    overflow = False
    for n, raw in adapter.iter_rows(path, limit=limit):
        result = adapter.normalize_row(raw, source_file=source_file, source_row=n)
        if not result.ok or result.event is None:
            continue
        event = dict(result.event)
        event["_ts"] = coerce_ts(event.get("timestamp"))
        moment = parse_ts(event.get("timestamp"))
        if moment is None:
            continue
        pair = (event.get("protocol"), event.get("destination_port"))
        if moment < split:
            catalog.add(pair)
            continue
        if pair in catalog:
            continue
        counts[pair] = counts.get(pair, 0) + 1
        bucket_ids.setdefault(pair, []).append((moment, event["event_id"]))
        buf = earliest.setdefault(pair, [])
        if len(buf) < 5 or moment < buf[-1][0]:
            buf.append((moment, event["event_id"], event))
            buf.sort(key=lambda t: (t[0], t[1]))
            del buf[5:]
        if len(counts) > max_pairs:
            overflow = True
            break
    info["overflow_pairs"] = overflow
    info["catalog_pairs"] = len(catalog)
    out = []
    threshold = config.novelty_min_flows
    for pair in sorted(counts, key=lambda p: (str(p[0]), str(p[1]))):
        if counts[pair] < threshold:
            continue
        proto, port = pair
        members = sorted(earliest[pair], key=lambda t: (t[0], t[1]))
        rows = [event for _, _, event in members[:5]]
        bucket = [{"event_id": eid} for _, eid in sorted(bucket_ids[pair])]
        out.append(make_result(
            rule.rule_id, rule.name, rule.severity, 0.5,
            (f"Unusual protocol/port combination observed: {proto}/{port} "
             f"({counts[pair]} flows), unseen in baseline period."),
            rows,
            {"protocol": proto, "destination_port": port,
             "count": counts[pair]},
            bucket=bucket))
    out.sort(key=lambda d: d.fingerprint)
    return out, info


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


def block_edge(block: list[dict], overlap: timedelta) -> datetime | None:
    """Newest block timestamp minus overlap, computed once per block."""
    moments = [parse_ts(e.get("timestamp")) for e in block]
    moments = [m for m in moments if m is not None]
    if not moments:
        return None
    return max(moments) - overlap


def _is_fresh(moment: datetime | None, edge: datetime | None) -> bool:
    return moment is not None and edge is not None and moment > edge


def _fresh(event: dict, block: list[dict], overlap: timedelta) -> bool:
    """Compatibility wrapper: edge recomputed per call (slow for large carry).

    Hot paths precompute block_edge() once and use _is_fresh() instead.
    """
    return _is_fresh(parse_ts(event.get("timestamp")), block_edge(block, overlap))


def _carry_events(block: list[dict], carry: list[dict], overlap: timedelta) -> list[dict]:
    edge = block_edge(block, overlap)
    if edge is None:
        return carry
    kept = [e for e in block + carry if (_is_fresh(parse_ts(e.get("timestamp")), edge))]
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
                  fp_notes: list[dict], leakage_ok: bool,
                  bucket: dict | None = None,
                  per_rule_bucket: dict | None = None,
                  incident: dict | None = None) -> dict:
    return {
        "run_id": run_id,
        "files": sorted(files),
        "params": params,
        "stats": stats,
        "per_rule": per_rule,
        "overall": overall,
        "label_coverage": coverage,
        "bucket": bucket,
        "per_rule_bucket": per_rule_bucket,
        "incident": incident,
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
        "Evidence-level metrics measure labelled event coverage from capped",
        "`evidence_event_ids` (caps 20/20/20/3/5/20 for FLOW-001..006);",
        "event-level recall therefore measures evidence coverage, not complete",
        "detection-bucket coverage.",
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
        "## Bucket-level metrics",
        "",
        "Each DetectionResult is one detection bucket (`bucket_event_ids`, the",
        "complete label-free contributor set). Bucket precision asks whether a",
        "detection bucket intersects attack activity; bucket recall asks whether",
        "each post-hoc label-defined attack episode was hit. Labels are resolved",
        "only after detection. The fixed 1M slice contains one non-benign attack",
        "label, so bucket recall is binary there; this is a property of the slice,",
        "not of CSE-CIC-IDS2018 generally. Bucket metrics complement rather than",
        "replace evidence-level metrics.",
        "",
    ]
    bucket = summary.get("bucket") or {}

    def show(value):
        if value is None:
            return "n/a"
        return f"{value:.3f}" if isinstance(value, float) else str(value)

    if bucket:
        lines.append(
            f"- detection buckets: {bucket['detection_bucket_count']} "
            f"(evaluated {bucket['evaluated_buckets']}, "
            f"unavailable {bucket['unavailable_buckets']})")
        lines.append(
            f"- bucket TP/FP: {bucket['bucket_tp']}/{bucket['bucket_fp']} "
            f"(precision {show(bucket['bucket_precision'])})")
        lines.append(
            f"- attack episodes hit: {bucket['attack_bucket_hit']}/"
            f"{bucket['attack_bucket_count']} "
            f"(recall {show(bucket['bucket_recall'])})")
        for rule_id, metrics in sorted((summary.get("per_rule_bucket") or {}).items()):
            lines.append(
                f"- {rule_id}: buckets {metrics['detection_bucket_count']}, "
                f"TP/FP {metrics['bucket_tp']}/{metrics['bucket_fp']} "
                f"(precision {show(metrics['bucket_precision'])}), episodes "
                f"{metrics['attack_bucket_hit']}/{metrics['attack_bucket_count']} "
                f"(recall {show(metrics['bucket_recall'])})")
        lines.append("")
    incident = summary.get("incident") or {}
    lines += [
        "## Incident-level metrics",
        "",
        "Incidents group detections with the application correlation engine;",
        "an incident is an attack hit iff its member buckets intersect an",
        "attack episode. No incident false-positive rate is reported: benign",
        "episodes are not a partition, so a conventional denominator would",
        "mislead. Incident metrics complement detection metrics.",
        "",
    ]
    if incident:
        lines.append(
            f"- incidents: {incident['total_incidents']} "
            f"(attack-hit {incident['attack_incidents']}, benign "
            f"{incident['benign_incidents']}, precision "
            f"{show(incident['incident_precision'])})")
        lines.append(
            f"- attack episodes hit: {incident['attack_bucket_hit']}/"
            f"{incident['attack_bucket_count']} "
            f"(recall {show(incident['incident_recall'])})")
        lines.append(
            f"- detections per incident: mean "
            f"{show(incident['detections_per_incident'])}, median "
            f"{show(incident['median_detections_per_incident'])}, max "
            f"{show(incident['max_detections_per_incident'])}")
        for composition, count in sorted((incident.get("rule_composition") or {}).items()):
            lines.append(f"- {composition}: {count} incident(s)")
        lines.append(
            f"- coverage: with buckets {incident['incidents_with_buckets']}, "
            f"with network {incident['incidents_with_network']}")
        lines.append("")
    lines += [
        "## Notes",
        "",
        "- Labels were read AFTER detection for reporting only.",
        "- Benchmark numbers measure lab behavior, not production efficacy.",
        "",
    ]
    return "\n".join(lines) + "\n"

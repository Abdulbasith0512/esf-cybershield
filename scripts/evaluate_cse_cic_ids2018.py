"""Evaluate flow detectors on CSE-CIC-IDS2018 files (dev/validation only).

Reads dataset labels AFTER detection for reporting only. Never persists
incidents, never tunes thresholds, never feeds labels to detectors.

Usage:
    python scripts/evaluate_cse_cic_ids2018.py --file 02-14-2018.csv --limit 10000
    python scripts/evaluate_cse_cic_ids2018.py --file 02-20-2018.csv --limit 5000 --chunk-rows 2000
    python scripts/evaluate_cse_cic_ids2018.py --file 02-14-2018.csv --sample 2000 --sample-seed 7
"""

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.services.datasets.cse_cic_ids2018 import ADAPTER_VERSION, CseCicIds2018Adapter  # noqa: E402
from app.services.detect.common import prepare  # noqa: E402
from app.services.datasets.evaluate import (  # noqa: E402
    BENIGN_LABEL,
    attribute,
    build_summary,
    chunked_detect,
    collect_evidence_labels,
    coverage_from_labels,
    label_by_event,
    label_coverage,
    overall_summary,
    render_markdown,
    reservoir_sample,
    rule_metrics,
    run_id_for,
    session_rule_sample,
    stratified_sample,
)
from app.services.detect.flow import detect_flows  # noqa: E402
from app.services.detect.flow.config import FlowConfig  # noqa: E402
from app.services.detect.flow.rules import ProtocolPortNovelty  # noqa: E402

DATA_DIR = Path(__file__).resolve().parents[1] / "data" / "public" / "cse_cic_ids2018" / "raw"
REPO = Path(__file__).resolve().parents[1]


def resolve_file(name: str) -> Path:
    candidate = Path(name)
    if candidate.is_file():
        return candidate
    fallback = DATA_DIR / Path(name).name
    if fallback.is_file():
        return fallback
    print(f"ERROR: input is not a file: {name}", file=sys.stderr)
    sys.exit(2)
    raise AssertionError("unreachable")


def adapt_all(adapter, path, source_file, limit):
    events, rejected, n = [], 0, 0
    for row_number, raw in adapter.iter_rows(path, limit=limit):
        n += 1
        result = adapter.normalize_row(raw, source_file=source_file, source_row=row_number)
        if result.ok and result.event is not None:
            events.append(result.event)
        else:
            rejected += 1
    return events, rejected, n


def adapt_all(adapter, path, source_file, limit):
    """Adapt a bounded file fully into memory. Rejects counted, never raised."""
    events, rejected, nrows = [], 0, 0
    for n, raw in adapter.iter_rows(path, limit=limit):
        nrows += 1
        result = adapter.normalize_row(raw, source_file=source_file, source_row=n)
        if result.ok and result.event is not None:
            events.append(result.event)
        else:
            rejected += 1
    return events, rejected, nrows


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate flow detectors on CSE-CIC-IDS2018.")
    parser.add_argument("--file", action="append", default=[],
                        help="CSV filename (resolved under data/) or path. Repeatable.")
    parser.add_argument("--limit", type=int, default=10000, help="Max rows per file (0 = unlimited).")
    parser.add_argument("--chunk-rows", type=int, default=0,
                        help="Stream in blocks of N rows (0 = accumulate in memory).")
    parser.add_argument("--overlap-minutes", type=int, default=40)
    parser.add_argument("--order", choices=["file", "time"], default="time",
                        help="Row processing order for chunked evaluation (default: time).")
    parser.add_argument("--sample", type=int, default=0,
                        help="Label-blind reservoir sample size (0 = all rows).")
    parser.add_argument("--balanced", type=int, default=0,
                        help="Label-stratified sample size. DIAGNOSTIC ONLY.")
    parser.add_argument("--sample-seed", type=int, default=42)
    parser.add_argument("--rules", default="", help="Comma-separated rule IDs to run (default: all).")
    parser.add_argument("--session-cap", type=int, default=50000,
                        help="Stride-sample cap for FLOW-005 under chunked mode.")
    parser.add_argument("--flow005-full", action="store_true",
                        help="Exact two-pass streaming FLOW-005 (complete catalog) "
                             "instead of stride sample under chunked mode.")
    parser.add_argument("--outdir", default="evaluation/cse_cic_ids2018")
    args = parser.parse_args()

    limit = None if args.limit == 0 else args.limit
    files = [str(resolve_file(f)) for f in (args.file or ["02-14-2018.csv"])]
    only_rules = {r.strip() for r in args.rules.split(",") if r.strip()} or None
    started = time.perf_counter()
    adapter = CseCicIds2018Adapter()
    config = FlowConfig()

    def select_rules():
        from app.services.detect.flow import default_flow_rules

        rules = default_flow_rules(config)
        return [r for r in rules if only_rules is None or r.rule_id in only_rules] or None

    all_events: list[dict] = []
    all_dets = []
    stats: dict[str, int] = {"rows": 0, "rejected": 0}
    chunked = args.chunk_rows > 0
    support_positive: int | None = None
    universe_size: int | None = None
    for path_str in files:
        path = Path(path_str)
        source_file = path.name
        if chunked:
            dets = chunked_detect(adapter, path, source_file, config,
                                  args.chunk_rows, args.overlap_minutes, limit,
                                  order=args.order)
            if only_rules is not None:
                dets = [d for d in dets if d.rule_id in only_rules]
            # Session-scoped rule: exact two-pass streaming when requested,
            # otherwise the documented bounded stride sample.
            if only_rules is None or "FLOW-005" in only_rules:
                if args.flow005_full:
                    from app.services.datasets.evaluate import evaluate_flow005_full

                    full, info = evaluate_flow005_full(adapter, path, source_file,
                                                       config, limit)
                    stats["flow005_mode"] = "full-catalog"
                    stats["flow005_overflow"] = info.get("overflow_pairs", False)
                    seen = {d.fingerprint for d in dets}
                    dets.extend(d for d in full if d.fingerprint not in seen)
                else:
                    sample = session_rule_sample(adapter, path, source_file,
                                                 args.session_cap, limit)
                    novice = ProtocolPortNovelty(config).evaluate(prepare(sample))
                    seen = {d.fingerprint for d in dets}
                    dets.extend(d for d in novice if d.fingerprint not in seen)
            all_dets.extend(dets)
        else:
            events, rejected, nrows = adapt_all(adapter, path, source_file, limit)
            stats["rows"] += nrows
            stats["rejected"] += rejected
            if args.sample > 0:
                events = reservoir_sample(events, args.sample, args.sample_seed)
                stats["sampled"] = len(events)
            dets = detect_flows(events, config=config, rules=select_rules())
            all_dets.extend(dets)
            all_events.extend(events)

    labels: dict[str, str] = {}
    label_totals: dict[str, int] = {}
    if chunked:
        # Second pass: labels + totals only; detectors already ran.
        wanted: set[str] = set()
        for det in all_dets:
            wanted.update(det.evidence_event_ids)
        totals: Counter[str] = Counter()
        for path_str in files:
            path = Path(path_str)
            got, tot, rej = collect_evidence_labels(
                adapter, path, path.name, wanted,
                limit if args.sample == 0 and args.balanced == 0 else None)
            labels.update(got)
            totals.update(tot)
            stats["rows"] += sum(tot.values())
            stats["rejected"] += rej
        label_totals = dict(totals)
        universe_size = sum(totals.values())
        support_positive = sum(n for lab, n in totals.items()
                               if lab not in (BENIGN_LABEL, "<empty>", ""))
    else:
        if args.balanced > 0:
            labeled = [((e.get("raw_event") or {}).get("evaluation_only", {}).get("label", ""), e)
                       for e in all_events]
            all_events = stratified_sample(labeled, args.balanced, args.sample_seed)
            stats["balanced"] = len(all_events)
            stats["balanced_diagnostic"] = True
        labels = label_by_event(all_events)
        label_totals = dict(Counter(labels.values()))

    params = {"limit": args.limit, "chunk_rows": args.chunk_rows,
              "overlap_minutes": args.overlap_minutes, "order": args.order,
              "sample": args.sample,
              "balanced": args.balanced, "sample_seed": args.sample_seed,
              "rules": sorted(only_rules) if only_rules else "all",
              "adapter": ADAPTER_VERSION, "session_cap": args.session_cap,
              "flow005_full": args.flow005_full}
    run_id = run_id_for(files, params)
    per_rule = rule_metrics(all_dets, labels, support_positive, universe_size)
    overall = overall_summary(all_dets, labels, support_positive, universe_size)
    coverage = coverage_from_labels(all_dets, labels, label_totals)

    fp_notes = []
    for det in sorted(all_dets, key=lambda d: d.fingerprint)[:20]:
        attr = attribute([det], labels)[det.detection_id]
        fp_notes.append({"rule_id": det.rule_id, "detection_id": det.detection_id,
                         "evidence": len(attr["covered"]),
                         "benign_evidence": len(attr["benign"]),
                         "reason": det.reason[:160]})
    summary = build_summary(run_id, files, params,
                            {"rows": stats.get("rows", 0), "events": len(all_events) or "streamed",
                             "detections": len(all_dets),
                             "runtime_s": round(time.perf_counter() - started, 1)},
                            per_rule, overall, coverage, fp_notes, True)
    outdir = Path(args.outdir)
    if not outdir.is_absolute():
        outdir = REPO / outdir
    outdir = outdir / run_id
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "summary.json").write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    (outdir / "report.md").write_text(render_markdown(summary), encoding="utf-8")
    print(render_markdown(summary))
    print(f"wrote {outdir / 'summary.json'}")
    print(f"BENIGN support label used: {BENIGN_LABEL!r} (evaluation reporting only)")


if __name__ == "__main__":
    main()

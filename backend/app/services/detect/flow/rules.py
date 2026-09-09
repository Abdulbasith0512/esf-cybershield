"""Network-flow detectors FLOW-001..FLOW-006. Telemetry only, hedged language.

Each rule implements the detect Rule protocol (evaluate over prepared rows)
and builds FlowViews internally, so rules never see dataset labels. All
thresholds live in FlowConfig; windows are inclusive-start / exclusive-end;
evidence is bounded head+tail.
"""

import math
from collections import Counter, deque
from datetime import datetime, timedelta
from statistics import median

from app.services.detect.flow.config import FlowConfig
from app.services.detect.flow.view import FlowView, build_views
from app.services.detect.models import DetectionResult, make_result

GLOBAL = "GLOBAL"


def _pairs(rows: list[dict]) -> list[tuple[FlowView, dict]]:
    views = build_views(rows)
    by_id = {r["event_id"]: r for r in rows}
    return [(v, by_id[v.event_id]) for v in views]


def _bounded(rows: list[dict], limit: int = 20) -> list[dict]:
    if len(rows) <= limit:
        return list(rows)
    half = limit // 2
    return rows[:half] + rows[-(limit - half):]


def _entity_key(*parts: str | None) -> str:
    return "|".join(p if p else "?" for p in parts)


def _ephemeral_port(port, config: FlowConfig) -> bool:
    """IANA dynamic/private range check for analyst context (metadata only)."""
    return (isinstance(port, int) and not isinstance(port, bool)
            and config.ephemeral_port_min <= port <= config.ephemeral_port_max)


class HighConnectionRate:
    """FLOW-001 High Connection Rate (MEDIUM). Volume vs own baseline."""

    rule_id = "FLOW-001"
    name = "High Connection Rate"
    description = "Flow count per key far above its recent baseline."
    severity = "MEDIUM"

    def __init__(self, config: FlowConfig = FlowConfig()):
        self.config = config

    def evaluate(self, events: list[dict]) -> list[DetectionResult]:
        pairs = [(v, r) for v, r in _pairs(events)]
        groups: dict[str, list[tuple[FlowView, dict]]] = {}
        for v, r in pairs:
            groups.setdefault(v.destination_ip or GLOBAL, []).append((v, r))
        out = []
        width = self.config.rate_window_seconds
        for key, members in groups.items():
            members.sort(key=lambda t: (t[0].ts, t[0].event_id))
            t0 = members[0][0].ts
            buckets: dict[int, list[tuple[FlowView, dict]]] = {}
            for item in members:
                idx = int((item[0].ts - t0).total_seconds() // width)
                buckets.setdefault(idx, []).append(item)
            span = range(0, max(buckets) + 1)
            counts = [len(buckets.get(i, [])) for i in span]
            for i in span:
                priors = counts[max(0, i - self.config.rate_baseline_windows):i]
                baseline = median(priors) if priors else 0
                threshold = max(self.config.rate_min_count,
                                self.config.rate_baseline_factor * baseline)
                bucket = buckets.get(i, [])
                if len(bucket) >= threshold and len(bucket) >= self.config.rate_min_count:
                    rows = [r for _, r in sorted(bucket, key=lambda t: (t[0].ts, t[0].event_id))]
                    n = len(rows)
                    out.append(make_result(
                        self.rule_id, self.name, self.severity,
                        min(0.55 + 0.05 * math.log2(n / threshold), 0.9),
                        (f"High-rate connection behavior detected: {n} flows to {key} "
                         f"within 60 seconds (baseline median {baseline})."),
                        _bounded(rows),
                        {"key": key, "count": n, "baseline_median": baseline,
                         "threshold": threshold},
                        bucket=rows))
        return out


class RepeatedAttempts:
    """FLOW-002 Repeated Connection Attempts, brute-force-like (HIGH)."""

    rule_id = "FLOW-002"
    name = "Repeated Connection Attempts"
    description = "Many short SYN-heavy flows to one service port."
    severity = "HIGH"

    def __init__(self, config: FlowConfig = FlowConfig()):
        self.config = config

    @staticmethod
    def _qualifying(view: FlowView) -> bool:
        syn = view.flow_value("SYN Flag Cnt")
        ack = view.flow_value("ACK Flag Cnt")
        total = (view.bytes_sent or 0) + (view.bytes_received or 0)
        return syn > ack and total < 10 * 1024

    def evaluate(self, events: list[dict]) -> list[DetectionResult]:
        groups: dict[str, list[tuple[FlowView, dict]]] = {}
        for v, r in _pairs(events):
            port = v.destination_port
            groups.setdefault(_entity_key(v.destination_ip or GLOBAL,
                                          str(port) if port is not None else "?"),
                              []).append((v, r))
        out = []
        window = timedelta(minutes=self.config.brute_window_minutes)
        for key, members in groups.items():
            members.sort(key=lambda t: (t[0].ts, t[0].event_id))
            # Incremental sliding window: each event enters once and leaves
            # once. `window_all` holds every event in the active window (for
            # expiry and window_count); `window_qual` holds only qualifying
            # ones in (ts, event_id) order. Firing clears both, matching the
            # reference start=end+1 reset exactly.
            window_all: deque[tuple[datetime, str, bool]] = deque()
            window_qual: deque[tuple[datetime, str, dict]] = deque()
            for v, r in members:
                ts = v.ts
                while window_all and ts - window_all[0][0] >= window:
                    _, _, was_qual = window_all.popleft()
                    if was_qual:
                        window_qual.popleft()
                qualifies = self._qualifying(v)
                window_all.append((ts, v.event_id, qualifies))
                if qualifies:
                    window_qual.append((ts, v.event_id, r))
                if len(window_qual) >= self.config.brute_min_flows:
                    n = len(window_qual)
                    rows = [row for _, _, row in window_qual]
                    out.append(make_result(
                        self.rule_id, self.name, self.severity,
                        min(0.60 + 0.02 * n, 0.9),
                        (f"Repeated connection attempts detected: {n} short SYN-heavy "
                         f"flows to {key} within 5 minutes."),
                        _bounded(rows),
                        {"key": key, "qualifying_count": n,
                         "window_count": len(window_all)},
                        bucket=rows))
                    window_all.clear()
                    window_qual.clear()
        return out


class PortScan:
    """FLOW-003 Port-Scan-like Behavior (MEDIUM). Endpoint-aware first."""

    rule_id = "FLOW-003"
    name = "Port-Scan-like Behavior"
    description = "One source contacting many distinct destination ports."
    severity = "MEDIUM"

    def __init__(self, config: FlowConfig = FlowConfig()):
        self.config = config

    def evaluate(self, events: list[dict]) -> list[DetectionResult]:
        pairs = _pairs(events)
        out = list(self._scan_mode(pairs))
        out.extend(self._entropy_fallback(pairs))
        return out

    @staticmethod
    def _is_probe(view: FlowView) -> bool:
        """Unanswered SYN probe: TCP with SYNs exceeding ACKs. Missing flag
        counts read as zero, so UDP, FIN-only, and unknown traffic fail
        closed instead of guessing."""
        return view.protocol == "TCP" and \
            view.flow_value("SYN Flag Cnt") > view.flow_value("ACK Flag Cnt")

    def _scan_mode(self, pairs):
        groups: dict[str, list[tuple[FlowView, dict]]] = {}
        for v, r in pairs:
            if v.source_ip:
                groups.setdefault(v.source_ip, []).append((v, r))
        window = timedelta(minutes=self.config.scan_window_minutes)
        dense = timedelta(seconds=self.config.scan_density_window_seconds)
        need = self.config.scan_min_ports
        out = []
        for ip, members in groups.items():
            members.sort(key=lambda t: (t[0].ts, t[0].event_id))
            # Incremental twin windows over the sorted members. outer holds
            # the 5-minute search context (port counts + distinct total);
            # inner holds the dense sub-window (per-port member queues).
            # Invariants match the previous per-event rebuild exactly: outer
            # is the maximal suffix ending at `end` within the outer window,
            # inner the maximal suffix within the density window and outer.
            outer_counts: Counter = Counter()
            outer_distinct = 0
            inner_counts: Counter = Counter()
            inner_distinct = 0
            inner_probes = 0
            queues: dict[int, deque[int]] = {}
            probe_first: dict[int, bool] = {}
            start = 0
            low = 0
            for end in range(len(members)):
                port = members[end][0].destination_port
                if port is not None:
                    if outer_counts[port] == 0:
                        outer_distinct += 1
                    outer_counts[port] += 1
                    if inner_counts[port] == 0:
                        inner_distinct += 1
                        probe = self._is_probe(members[end][0])
                        probe_first[port] = probe
                        if probe:
                            inner_probes += 1
                    inner_counts[port] += 1
                    queues.setdefault(port, deque()).append(end)
                while members[end][0].ts - members[start][0].ts >= window:
                    old = members[start][0].destination_port
                    if old is not None:
                        outer_counts[old] -= 1
                        if outer_counts[old] == 0:
                            outer_distinct -= 1
                    if low == start and old is not None:
                        inner_counts[old] -= 1
                        if inner_counts[old] == 0:
                            inner_distinct -= 1
                        queues[old].popleft()
                        if queues[old]:
                            new_probe = self._is_probe(members[queues[old][0]][0])
                            if new_probe != probe_first[old]:
                                probe_first[old] = new_probe
                                inner_probes += 1 if new_probe else -1
                        elif probe_first.pop(old, False):
                            inner_probes -= 1
                        low += 1
                    start += 1
                while members[end][0].ts - members[low][0].ts >= dense:
                    drop = members[low][0].destination_port
                    if drop is not None:
                        inner_counts[drop] -= 1
                        if inner_counts[drop] == 0:
                            inner_distinct -= 1
                        queues[drop].popleft()
                        if queues[drop]:
                            new_probe = self._is_probe(members[queues[drop][0]][0])
                            if new_probe != probe_first[drop]:
                                probe_first[drop] = new_probe
                                inner_probes += 1 if new_probe else -1
                        elif probe_first.pop(drop, False):
                            inner_probes -= 1
                    low += 1
                if outer_distinct >= need and inner_distinct >= need and \
                        inner_probes / inner_distinct > self.config.scan_unanswered_syn_fraction:
                    by_dense = {p: members[q[0]] for p, q in queues.items() if q}
                    chosen = [by_dense[p] for p in sorted(by_dense)[:20]]
                    chosen.sort(key=lambda t: (t[0].ts, t[0].event_id))
                    rows = [r for _, r in chosen]
                    # Full distinct-port set of the dense span; evidence above
                    # keeps the first 20.
                    bucket_rows = [r for _, r in sorted(
                        by_dense.values(), key=lambda t: (t[0].ts, t[0].event_id))]
                    out.append(make_result(
                        self.rule_id, self.name, self.severity,
                        min(0.55 + 0.02 * len(by_dense), 0.85),
                        (f"Port-scan-like behavior detected: {len(by_dense)} distinct "
                         f"destination ports contacted from {ip} within 5 minutes."),
                        rows,
                        {"source_ip": ip, "distinct_ports": len(by_dense)},
                        bucket=bucket_rows))
                    start = end + 1
                    low = end + 1
                    outer_counts.clear()
                    inner_counts.clear()
                    queues.clear()
                    probe_first.clear()
                    outer_distinct = 0
                    inner_distinct = 0
                    inner_probes = 0
        return out

    def _entropy_fallback(self, pairs):
        """Weak flow-only fallback: global per-minute destination-port Shannon
        entropy. Labeled as entropy anomaly, never as a scan. Any source_ip
        presence disables it (scan mode already covers that ground)."""
        if any(v.source_ip for v, _ in pairs):
            return []
        buckets: dict[int, list[tuple[FlowView, dict]]] = {}
        epoch = datetime(1970, 1, 1)  # naive-UTC minute buckets, machine-independent
        for v, r in pairs:
            if v.destination_port is None:
                continue
            idx = int((v.ts - epoch).total_seconds() // 60)
            buckets.setdefault(idx, []).append((v, r))
        out = []
        for idx in sorted(buckets):
            bucket = buckets[idx]
            if len(bucket) < self.config.scan_min_ports:
                continue
            counts = Counter(v.destination_port for v, _ in bucket)
            total = sum(counts.values())
            entropy = -sum((c / total) * math.log2(c / total) for c in counts.values())
            if entropy >= self.config.scan_entropy_threshold:
                rows = [r for _, r in sorted(bucket, key=lambda t: (t[0].ts, t[0].event_id))[:20]]
                full_rows = [r for _, r in sorted(bucket, key=lambda t: (t[0].ts, t[0].event_id))]
                out.append(make_result(
                    self.rule_id, "Port Entropy Anomaly", self.severity,
                    min(0.5 + 0.05 * entropy, 0.8),
                    (f"Port-entropy anomaly detected: destination-port entropy "
                     f"{entropy:.2f} bits across {len(bucket)} flows in one minute. "
                     f"This is not attributed to any source."),
                    rows,
                    {"entropy_bits": round(entropy, 3), "flow_count": len(bucket),
                     "mode": "global-fallback"},
                    bucket=full_rows))
        return out


class ByteRateAnomaly:
    """FLOW-004 Flow Byte-Rate Anomaly (MEDIUM). Rate vs rolling baseline.

    The bucket signal is the median per-flow byte rate over buckets holding
    at least byte_min_bucket_flows flows, so one huge legitimate transfer
    cannot trip the rule; the trailing-median baseline test is unchanged.
    """

    rule_id = "FLOW-004"
    name = "Flow Byte-Rate Anomaly"
    description = "Flows moving bytes far faster than the recent norm."
    severity = "MEDIUM"

    def __init__(self, config: FlowConfig = FlowConfig()):
        self.config = config

    def evaluate(self, events: list[dict]) -> list[DetectionResult]:
        groups: dict[str, list[tuple[FlowView, dict]]] = {}
        for v, r in _pairs(events):
            groups.setdefault(v.destination_ip or GLOBAL, []).append((v, r))
        out = []
        width = self.config.byte_window_seconds
        hist = self.config.byte_min_history_buckets
        span_buckets = self.config.byte_baseline_minutes * 60 // width
        for key, members in groups.items():
            members.sort(key=lambda t: (t[0].ts, t[0].event_id))
            t0 = members[0][0].ts
            buckets: dict[int, list[tuple[FlowView, dict]]] = {}
            for item in members:
                idx = int((item[0].ts - t0).total_seconds() // width)
                buckets.setdefault(idx, []).append(item)
            peaks = {i: max(v.flow_value("Flow Byts/s") for v, _ in b)
                     for i, b in buckets.items()}
            for i in sorted(buckets):
                if len(buckets[i]) < self.config.byte_min_bucket_flows:
                    continue
                signal = median(v.flow_value("Flow Byts/s") for v, _ in buckets[i])
                prior = [peaks[j] for j in range(max(0, i - span_buckets), i) if j in peaks]
                if len(prior) < hist:
                    continue
                baseline = median(prior)
                floor = self.config.byte_floor
                if baseline <= 0:
                    fires = signal >= floor and signal >= self.config.byte_ratio * floor
                    ratio = signal / floor if floor else 0
                else:
                    fires = signal >= self.config.byte_ratio * baseline and signal >= floor
                    ratio = signal / baseline
                if fires:
                    ranked = sorted(buckets[i],
                                    key=lambda t: (-t[0].flow_value("Flow Byts/s"),
                                                   t[0].event_id))
                    rows = [r for _, r in ranked[:3]]
                    # Evidence is rate-ranked; bucket keeps full time order.
                    bucket_rows = [r for _, r in sorted(
                        buckets[i], key=lambda t: (t[0].ts, t[0].event_id))]
                    out.append(make_result(
                        self.rule_id, self.name, self.severity,
                        min(0.55 + 0.1 * math.log2(max(ratio, 1.0)), 0.85),
                        (f"Anomalous flow byte rate detected: median {signal:,.0f} B/s "
                         f"vs {baseline:,.0f} B/s recent median."),
                        rows,
                        {"key": key, "median_byts": signal,
                         "baseline_median": baseline, "ratio": round(ratio, 2)},
                        bucket=bucket_rows))
        return out


class ProtocolPortNovelty:
    """FLOW-005 Protocol/Port Anomaly (LOW). Novelty tripwire, not cannon.

    Novelty alone never fires: a novel pair must also reach peak minute-level
    volume (config.novelty_min_peak within one UTC minute bucket), so routine
    ephemeral-port churn stays silent while sustained novel services fire.
    """

    rule_id = "FLOW-005"
    name = "Protocol/Port Anomaly"
    description = "Protocol/port pairs unseen in the baseline period."
    severity = "LOW"

    def __init__(self, config: FlowConfig = FlowConfig()):
        self.config = config

    @staticmethod
    def _minute_bucket(moment: datetime) -> int:
        epoch = datetime(1970, 1, 1)  # naive-UTC minute buckets, machine-independent
        return int((moment - epoch).total_seconds() // 60)

    def evaluate(self, events: list[dict]) -> list[DetectionResult]:
        pairs = _pairs(events)
        if not pairs:
            return []
        stamps = sorted(v.ts for v, _ in pairs)
        split = stamps[0] + (stamps[-1] - stamps[0]) / 3
        catalog = {(v.protocol, v.destination_port) for v, _ in pairs if v.ts < split}
        novel: dict[tuple, list[tuple[FlowView, dict]]] = {}
        for item in pairs:
            v = item[0]
            if v.ts >= split:
                key = (v.protocol, v.destination_port)
                if key in catalog:
                    continue
                novel.setdefault(key, []).append(item)
        out = []
        for (proto, port), members in sorted(novel.items(), key=lambda kv: (str(kv[0][0]), str(kv[0][1]))):
            if len(members) < self.config.novelty_min_flows:
                continue
            members.sort(key=lambda t: (t[0].ts, t[0].event_id))
            peak = 0
            if members:
                per_minute: dict[int, int] = {}
                for view, _ in members:
                    minute = self._minute_bucket(view.ts)
                    per_minute[minute] = per_minute.get(minute, 0) + 1
                peak = max(per_minute.values())
            if peak < self.config.novelty_min_peak:
                continue
            rows = [r for _, r in members[:5]]
            out.append(make_result(
                self.rule_id, self.name, self.severity, 0.5,
                (f"Unusual protocol/port combination observed: {proto}/{port} "
                 f"({len(members)} flows), unseen in baseline period."),
                rows,
                {"protocol": proto, "destination_port": port,
                 "count": len(members), "peak_minute_count": peak,
                 "ephemeral_port": _ephemeral_port(port, self.config)},
                bucket=[r for _, r in members]))
        return out


class VolumeBurst:
    """FLOW-006 DoS-like High-Volume Burst (HIGH)."""

    rule_id = "FLOW-006"
    name = "DoS-like High-Volume Burst"
    description = "Extreme packet/flow surges in short windows."
    severity = "HIGH"

    def __init__(self, config: FlowConfig = FlowConfig()):
        self.config = config

    @staticmethod
    def _packets(view: FlowView) -> float:
        return view.flow_value("Tot Fwd Pkts") + view.flow_value("Tot Bwd Pkts")

    @staticmethod
    def _rate(view: FlowView) -> float:
        explicit = view.flow.get("Flow Pkts/s")
        if explicit:
            return explicit
        return 0.0

    def evaluate(self, events: list[dict]) -> list[DetectionResult]:
        groups: dict[str, list[tuple[FlowView, dict]]] = {}
        for v, r in _pairs(events):
            groups.setdefault(v.destination_ip or GLOBAL, []).append((v, r))
        out = []
        width = self.config.burst_window_seconds
        for key, members in groups.items():
            members.sort(key=lambda t: (t[0].ts, t[0].event_id))
            t0 = members[0][0].ts
            buckets: dict[int, list[tuple[FlowView, dict]]] = {}
            for item in members:
                idx = int((item[0].ts - t0).total_seconds() // width)
                buckets.setdefault(idx, []).append(item)
            for i in sorted(buckets):
                bucket = buckets[i]
                if len(bucket) < self.config.burst_min_flows:
                    continue
                total_packets = sum(self._packets(v) for v, _ in bucket)
                aggregate = total_packets / width
                if aggregate < self.config.burst_min_pps:
                    continue
                ranked = sorted(bucket, key=lambda t: (-self._rate(t[0]),
                                                       -self._packets(t[0]),
                                                       t[0].event_id))
                rows = [r for _, r in ranked[:20]]
                # Evidence is rate-ranked; bucket keeps full time order.
                bucket_rows = [r for _, r in sorted(
                    bucket, key=lambda t: (t[0].ts, t[0].event_id))]
                out.append(make_result(
                    self.rule_id, self.name, self.severity,
                    min(0.65 + 0.05 * math.log10(aggregate / self.config.burst_min_pps), 0.9),
                    (f"Denial-of-service-like traffic pattern detected: {len(bucket)} "
                     f"flows, {aggregate:,.0f} packets/s within 30 seconds."),
                    rows,
                    {"key": key, "flow_count": len(bucket),
                     "packets_per_s": round(aggregate, 1)},
                    bucket=bucket_rows))
        return out

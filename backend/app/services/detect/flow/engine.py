"""Network-flow detection entry point. Mirrors engine.detect; touches nothing existing.

Flow rules implement the detect Rule protocol, so they can also run through
engine.detect(rules=[...]). This wrapper only wires the flow registry.
"""

import logging

from app.services.detect.common import prepare
from app.services.detect.flow.config import FlowConfig
from app.services.detect.models import DetectionResult

logger = logging.getLogger("esf.detect.flow")


def detect_flows(events: list[dict], config: FlowConfig | None = None,
                 rules=None) -> list[DetectionResult]:
    """Run flow rules over timestamp-sorted events.

    Deterministic: identical input + config -> identical output (results
    sorted by fingerprint). Never modifies inputs, never touches the DB,
    never creates incidents, never reads dataset labels.
    """
    config = config or FlowConfig()
    rows = prepare(events)
    if rules is None:
        from app.services.detect.flow import default_flow_rules  # noqa: E402 - avoid circular import

        rules = default_flow_rules(config)
    active = rules
    results: list[DetectionResult] = []
    for rule in active:
        try:
            results.extend(rule.evaluate(rows))
        except Exception:  # noqa: BLE001 -- one bad rule must not kill the run
            logger.exception("flow rule failed: %s", getattr(rule, "rule_id", "?"))
    seen, unique = set(), []
    for r in results:
        if r.fingerprint not in seen:
            seen.add(r.fingerprint)
            unique.append(r)
    unique.sort(key=lambda r: r.fingerprint)
    logger.info("flow detection run: %d events -> %d detections", len(events), len(unique))
    return unique

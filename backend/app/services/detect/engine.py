"""Detection engine: sort, execute registered rules, dedupe. No rule logic here."""

import logging

from app.services.detect.common import prepare
from app.services.detect.config import DetectorConfig
from app.services.detect.models import DetectionResult
from app.services.detect.rules import default_rules

logger = logging.getLogger("esf.detect")


def detect(events: list[dict], config: DetectorConfig | None = None,
           rules=None) -> list[DetectionResult]:
    """Run all registered rules over timestamp-sorted events.

    Deterministic: identical input + config -> identical output (results
    sorted by fingerprint). Never modifies inputs, never touches the DB,
    never creates incidents.
    """
    config = config or DetectorConfig()
    rows = prepare(events)
    active = rules if rules is not None else default_rules(config)
    results: list[DetectionResult] = []
    for rule in active:
        try:
            results.extend(rule.evaluate(rows))
        except Exception:  # noqa: BLE001 -- one bad rule must not kill the run
            logger.exception("rule failed: %s", getattr(rule, "rule_id", "?"))
    seen, unique = set(), []
    for r in results:
        if r.fingerprint not in seen:
            seen.add(r.fingerprint)
            unique.append(r)
    unique.sort(key=lambda r: r.fingerprint)
    logger.info("detection run: %d events -> %d detections", len(events), len(unique))
    return unique

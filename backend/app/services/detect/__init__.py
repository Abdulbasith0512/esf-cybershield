"""Detection engine package. Deterministic, stateless, persistence-free.

Pipeline: events (list of plain dicts) -> engine.detect() -> DetectionResult.
Rules never see ground truth (scenario_id / scenario_type / synthetic live
inside raw_event, which no rule reads). No ML, no LLM, no incidents.
"""

from app.services.detect.engine import detect
from app.services.detect.models import DetectionResult

__all__ = ["DetectionResult", "detect"]

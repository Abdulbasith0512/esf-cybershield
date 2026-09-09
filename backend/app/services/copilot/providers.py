"""LLM provider abstraction: fake (offline default) + Ollama (planned stack).

No API keys anywhere: the fake provider needs none, and Ollama local
inference uses none. Detection/investigation never import this module, so a
provider outage cannot affect the pipeline. Exactly one network attempt per
request, bounded by timeout; no retries.
"""

import json
import re
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass

FAKE_PROVIDER = "fake"
OLLAMA_PROVIDER = "ollama"

_STATE_CHANGE_RES = [
    re.compile(r"\bresolv\w*\b|\bclos\w*\b.*incident", re.IGNORECASE),
    re.compile(r"\bassign\b|\breassign\b", re.IGNORECASE),
    re.compile(r"\bquarantine\b|\bblock\b|\bkill\b|\bisolat\w*\b|\bcontain\b", re.IGNORECASE),
    re.compile(r"\badd\b.{0,20}\bnote\b", re.IGNORECASE),
]

_INJECTION_RES = [
    re.compile(r"ignore\s+(all\s+)?prev(ious)?\s+instructions", re.IGNORECASE),
    re.compile(r"disregard\s+", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+", re.IGNORECASE),
    re.compile(r"\breport\b.{0,40}\bas\s+safe\b", re.IGNORECASE),
]

_UNAVAILABLE_HINTS = ("hash", "malware", "attribut", "actor", "campaign",
                      "countr", "geograph", "exploit name", "cve-")


class LLMError(RuntimeError):
    """Provider request failed (transport, timeout, or bad payload)."""


@dataclass
class LLMResult:
    text: str
    provider: str = FAKE_PROVIDER
    model: str = "fake-v1"
    input_tokens: int | None = None
    output_tokens: int | None = None


class LLMProvider(ABC):
    """Provider contract. Pure text in, text out; grounding happens in the
    service layer so every provider inherits citation validation."""

    name: str = "base"

    @abstractmethod
    def generate(self, system_prompt: str, user_prompt: str, *,
                 timeout_seconds: float = 30.0,
                 max_output_tokens: int = 1024,
                 temperature: float = 0.0) -> LLMResult:
        raise NotImplementedError


def _det_refs(context: dict) -> tuple[list[str], list[str]]:
    ids = [d.get("detection_id", "") for d in context.get("detections") or []]
    tags = [f"[DET:{d}]" for d in ids if d]
    return ids, tags


class FakeLLMProvider(LLMProvider):
    """Deterministic offline provider for tests and unconfigured deployments.

    Answers are template compositions over context facts only: every
    identifier emitted comes from the context, so citation validation can
    only confirm. Never follows instructions embedded in data or questions.
    """

    name = FAKE_PROVIDER

    def __init__(self, model: str = "fake-v1") -> None:
        self.model = model

    def generate(self, system_prompt: str, user_prompt: str, *,
                 timeout_seconds: float = 30.0,
                 max_output_tokens: int = 1024,
                 temperature: float = 0.0) -> LLMResult:
        context = _context_from_prompt(user_prompt)
        question = _question_from_prompt(user_prompt)
        text = self._answer(context, question)
        return LLMResult(text=text, provider=self.name, model=self.model)

    def _answer(self, context: dict, question: str) -> str:
        incident = context.get("incident") or {}
        title = incident.get("title", "")
        severity = incident.get("severity", "")
        if _matches(question, _STATE_CHANGE_RES):
            return ("I cannot change incident state through the Copilot. "
                    "Use the case-management controls to change the incident status, "
                    "assignee, or notes. No action has been executed.")
        if _matches(question, _INJECTION_RES):
            return self._summary(context, title, severity) + (
                " I answer only from the provided incident evidence and do not "
                "follow instructions embedded in data or questions.")
        lowered = question.lower()
        if any(k in lowered for k in _UNAVAILABLE_HINTS):
            return "Not available in the provided incident evidence."
        if "summar" in lowered:
            return self._summary(context, title, severity)
        if any(k in lowered for k in ("why", "created", "reason", "explain")):
            return self._why(context, title)
        if any(k in lowered for k in ("timeline", "chronolog", "order", "sequence", "walk")):
            return self._timeline(context)
        if any(k in lowered for k in ("evidence", "support", "proof")):
            return self._evidence(context)
        if any(k in lowered for k in ("mitre", "technique", "tactic", "att&ck", "attack")):
            return self._mitre(context)
        if any(k in lowered for k in ("ueba", "anomal", "behavior", "behaviour", "baseline")):
            return self._ueba(context)
        if any(k in lowered for k in ("threat", "intel", "ioc", "reputation", "indicator")):
            return self._threat_intel(context)
        if any(k in lowered for k in ("investig", "next", "step", "recommend", "should i")):
            return self._next_steps(context)
        return self._summary(context, title, severity) + " " + self._next_steps(context)

    def _summary(self, context: dict, title: str, severity: str) -> str:
        incident = context.get("incident") or {}
        risk = context.get("risk") or {}
        _, tags = _det_refs(context)
        lines = [
            "Summary",
            (f"Incident '{title}' ({severity}) groups "
             f"{incident.get('detection_count', 0)} detection(s) "
             f"({', '.join(sorted({d.get('rule_id', '') for d in context.get('detections') or [] if d.get('rule_id')})) or 'no rules'}). "
             f"Risk {risk.get('score', incident.get('risk_score'))} ({risk.get('band', incident.get('risk_band'))})."),
            "Observed evidence",
            (f"{incident.get('evidence_count', 0)} evidence event(s) across "
             f"{len(tags)} detection(s): {', '.join(tags) or 'none'}."),
            "Interpretation",
            (context.get("explanation") or {}).get("summary", "") or
            "The detections were correlated into one incident by shared entities.",
            "Uncertainties",
            ("Technique and anomaly associations are hypotheses from stored mappings, "
             "not proof of attacker activity."),
            "Recommended next steps",
            "Review the detection timeline and entity summary before drawing conclusions.",
        ]
        return "\n".join(lines)

    def _why(self, context: dict, title: str) -> str:
        explanation = context.get("explanation") or {}
        factors = "; ".join(
            f"{f.get('factor', '')} (+{f.get('points', 0)})"
            for f in explanation.get("risk_factors") or [])
        _, tags = _det_refs(context)
        triggers = ", ".join(
            f"[DET:{d}]" for d in explanation.get("trigger_detections") or [])
        return (
            f"Incident '{title}' was created because correlated detections "
            f"({', '.join(tags) or 'none'}) shared entities within the correlation window. "
            f"Correlation: {explanation.get('correlation_reason', 'not recorded')} "
            f"Trigger detections: {triggers or 'none recorded'}. "
            f"Risk factors: {factors or 'none recorded'}."
        )

    def _timeline(self, context: dict) -> str:
        entries = context.get("timeline") or []
        if not entries:
            return "Not available in the provided incident evidence."
        lines = ["Activity in chronological order:"]
        for item in entries:
            lines.append(
                f"{item.get('first_seen', '')} {item.get('rule_id', '')} "
                f"[DET:{item.get('detection_id', '')}] "
                f"({item.get('evidence_count', 0)} evidence events).")
        return "\n".join(lines)

    def _evidence(self, context: dict) -> str:
        detections = context.get("detections") or []
        if not detections:
            return "Not available in the provided incident evidence."
        lines = [f"{context.get('evidence_total', 0)} evidence event(s) support this incident:"]
        for det in detections:
            refs = " ".join(f"[EVID:{e}]" for e in det.get("evidence_event_ids") or [])
            lines.append(
                f"[DET:{det.get('detection_id', '')}] {det.get('rule_id', '')}: "
                f"{det.get('evidence_count', 0)} event(s) {refs}".rstrip())
            if det.get("reason"):
                lines.append(f"Finding: {det.get('reason')}")
        missing = context.get("missing_detections") or []
        if missing:
            lines.append(f"Referenced but unavailable: {', '.join(missing)}.")
        return "\n".join(lines)

    def _mitre(self, context: dict) -> str:
        mappings = context.get("mitre_techniques") or []
        if not mappings:
            return "No MITRE ATT&CK mappings are stored for this incident."
        lines = ["Stored technique associations (hypotheses, not proof of use):"]
        for mapping in mappings:
            get = (lambda k: mapping.get(k, "")) if isinstance(mapping, dict) \
                else (lambda k: getattr(mapping, k, ""))
            lines.append(
                f"[MITRE:{get('technique_id')}] {get('technique_name')} "
                f"[{get('tactic')}] via {get('source_rule_id')}. {get('rationale')}")
        return "\n".join(lines)

    def _ueba(self, context: dict) -> str:
        ueba = context.get("ueba") or {}
        if not ueba.get("available"):
            return "No UEBA evidence is available for this incident."
        observations = ueba.get("observations") or []
        lines = [f"UEBA anomaly flag: {ueba.get('anomaly_flag')} "
                 f"(score {ueba.get('anomaly_score')})."]
        for observation in observations:
            get = (lambda k: observation.get(k)) if isinstance(observation, dict) \
                else (lambda k: getattr(observation, k, None))
            lines.append(f"[UEBA:{get('entity_key')}] score {get('anomaly_score')}.")
        return "\n".join(lines)

    def _threat_intel(self, context: dict) -> str:
        items = context.get("threat_intelligence") or []
        if not items:
            return "No threat-intelligence enrichment is available for this incident."
        lines = ["Provider-reported context (classifications are the provider's, not verdicts):"]
        for entry in items:
            if not entry.get("available"):
                lines.append(f"[TI:{entry.get('normalized_value', '')}] unavailable.")
                continue
            lines.append(
                f"[TI:{entry.get('normalized_value', '')}] "
                f"{entry.get('classification', 'unknown')} "
                f"(confidence {entry.get('confidence', 0.0)}) via {entry.get('provider', '')}.")
        return "\n".join(lines)

    def _next_steps(self, context: dict) -> str:
        recs = context.get("recommendations") or []
        if not recs:
            return ("Review the detection timeline and validate whether the observed "
                    "activity is expected in this environment.")
        lines = ["Suggested investigation steps (advisory only, nothing executed):"]
        for rec in recs[:5]:
            lines.append(f"{rec.get('title', '')}: {(rec.get('actions') or [''])[0]}")
        return "\n".join(lines)


def _matches(question: str, patterns: list) -> bool:
    return any(p.search(question or "") for p in patterns)


def _context_from_prompt(user_prompt: str) -> dict:
    """Recover the delimited context block the service embedded."""
    try:
        block = user_prompt.split("<INCIDENT_CONTEXT>")[1].split("</INCIDENT_CONTEXT>")[0]
        lines = block.splitlines()
        start = next(i for i, line in enumerate(lines) if line.lstrip().startswith("{"))
        data = json.loads("\n".join(lines[start:]))
        return data if isinstance(data, dict) else {}
    except (IndexError, ValueError, StopIteration):
        return {}


def _question_from_prompt(user_prompt: str) -> str:
    try:
        return user_prompt.split("Analyst question:")[1].strip()
    except IndexError:
        return ""


class OllamaProvider(LLMProvider):
    """Local Ollama inference over HTTP. No API keys; single bounded attempt."""

    name = OLLAMA_PROVIDER

    def __init__(self, host: str, model: str) -> None:
        self.host = (host or "").rstrip("/")
        self.model = model or "llama3.1"

    def generate(self, system_prompt: str, user_prompt: str, *,
                 timeout_seconds: float = 30.0,
                 max_output_tokens: int = 1024,
                 temperature: float = 0.0) -> LLMResult:
        if not self.host:
            raise LLMError("ollama host is not configured")
        payload = json.dumps({
            "model": self.model,
            "system": system_prompt,
            "prompt": user_prompt,
            "stream": False,
            "options": {"temperature": temperature, "num_predict": max_output_tokens},
        }).encode("utf-8")
        request = urllib.request.Request(
            f"{self.host}/api/generate", data=payload,
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=max(timeout_seconds, 0.1)) as response:
                body = json.loads(response.read().decode("utf-8"))
        except Exception as exc:
            raise LLMError(f"ollama request failed: {type(exc).__name__}") from exc
        text = body.get("response", "")
        if not isinstance(text, str) or not text.strip():
            raise LLMError("ollama returned an empty response")
        return LLMResult(text=text, provider=self.name, model=self.model,
                         input_tokens=body.get("prompt_eval_count"),
                         output_tokens=body.get("eval_count"))


def provider_registry(host: str = "", model: str = "") -> dict[str, LLMProvider]:
    """Available providers. Fake always ships; Ollama joins when configured."""
    fake = FakeLLMProvider(model=model or "fake-v1")
    registry: dict[str, LLMProvider] = {fake.name: fake}
    if host:
        ollama = OllamaProvider(host=host, model=model or "llama3.1")
        registry[ollama.name] = ollama
    return registry

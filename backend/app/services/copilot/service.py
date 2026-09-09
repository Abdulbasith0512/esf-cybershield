"""Copilot Q&A orchestration. Read-only; provider errors become 503s, never
500s. Citation validation runs on every answer so history or provider prose
can never mint evidence references."""

from datetime import datetime, timezone
from typing import Any

from app.services.copilot.context import MAX_CONTEXT_QUESTION_HISTORY, build_copilot_context
from app.services.copilot.grounding import extract_citations
from app.services.copilot.prompts import SYSTEM_PROMPT, build_user_prompt
from app.services.copilot.providers import LLMError, LLMProvider


class InvalidQuestion(ValueError):
    """Question failed validation (empty or over the length bound)."""


class CopilotUnavailable(RuntimeError):
    """No usable provider answer (unconfigured, failed, or timed out)."""


def validate_question(question: object, max_length: int) -> str:
    if not isinstance(question, str) or not question.strip():
        raise InvalidQuestion("question must be a non-empty string")
    cleaned = question.strip()
    if len(cleaned) > max_length:
        raise InvalidQuestion(f"question exceeds {max_length} characters")
    return cleaned


def _history(history: list[dict[str, str]] | None) -> list[dict[str, str]]:
    turns = []
    for turn in list(history or [])[-MAX_CONTEXT_QUESTION_HISTORY:]:
        if not isinstance(turn, dict):
            continue
        role = "user" if turn.get("role") == "user" else "assistant"
        content = str(turn.get("content", ""))[:2000]
        turns.append({"role": role, "content": content})
    return turns


def ask_copilot(incident_id: str, question: str, investigation: dict[str, Any],
                threat_intel: list | None, recommendations: list[dict[str, Any]] | None,
                provider: LLMProvider, *, history: list[dict[str, str]] | None = None,
                max_question_length: int = 2000, timeout_seconds: float = 30.0,
                max_output_tokens: int = 1024, temperature: float = 0.0,
                now: datetime | None = None) -> dict[str, Any]:
    """Answer one incident-scoped question. Never mutates inputs or storage."""
    cleaned = validate_question(question, max_question_length)
    context = build_copilot_context(investigation, threat_intel, recommendations)
    user_prompt = build_user_prompt(context, cleaned, _history(history))
    try:
        result = provider.generate(
            SYSTEM_PROMPT, user_prompt, timeout_seconds=timeout_seconds,
            max_output_tokens=max_output_tokens, temperature=temperature)
    except LLMError as exc:
        raise CopilotUnavailable(str(exc)) from exc
    except Exception as exc:  # defensive: provider bugs degrade, never 500
        raise CopilotUnavailable(f"provider failed: {type(exc).__name__}") from exc
    answer = (result.text or "").strip()
    if not answer:
        raise CopilotUnavailable("provider returned an empty response")
    citations, dropped = extract_citations(answer, context)
    moment = now or datetime.now(timezone.utc)
    response: dict[str, Any] = {
        "incident_id": incident_id,
        "question": cleaned,
        "answer": answer,
        "citations": citations,
        "grounded": True,
        "available": True,
        "provider": result.provider,
        "model": result.model,
        "generated_at": moment.astimezone(timezone.utc).isoformat(),
        "dropped_citations": dropped,
    }
    if result.input_tokens is not None or result.output_tokens is not None:
        response["usage"] = {"input_tokens": result.input_tokens,
                             "output_tokens": result.output_tokens}
    return response

"""SOC Analyst Copilot. Grounded analyst assistance, never source of truth.

Pipeline: incident -> investigation builder -> structured copilot context
-> provider -> grounded response + validated citations. The LLM only ever
sees the controlled context built here; it never queries the database and
never mutates anything.
"""

from app.services.copilot.context import SUGGESTED_QUESTIONS, build_copilot_context
from app.services.copilot.grounding import contains_injection, extract_citations
from app.services.copilot.prompts import SYSTEM_PROMPT, build_user_prompt
from app.services.copilot.providers import (
    FakeLLMProvider,
    LLMError,
    LLMResult,
    LLMProvider,
    OllamaProvider,
    provider_registry,
)
from app.services.copilot.service import (
    CopilotUnavailable,
    InvalidQuestion,
    ask_copilot,
)

__all__ = [
    "CopilotUnavailable",
    "FakeLLMProvider",
    "InvalidQuestion",
    "LLMError",
    "LLMProvider",
    "LLMResult",
    "OllamaProvider",
    "SUGGESTED_QUESTIONS",
    "SYSTEM_PROMPT",
    "ask_copilot",
    "build_copilot_context",
    "build_user_prompt",
    "contains_injection",
    "extract_citations",
    "provider_registry",
]

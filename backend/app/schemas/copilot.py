"""Pydantic contracts for the Slice 42 analyst-copilot API."""

from typing import Any, Literal

from pydantic import BaseModel, Field


class ChatTurn(BaseModel):
    model_config = {"extra": "forbid"}

    role: Literal["user", "assistant"] = "user"
    content: str = ""


class CopilotQuestion(BaseModel):
    """One incident-scoped question. Provider/model stay server-controlled."""

    model_config = {"extra": "forbid"}

    question: str = ""
    history: list[ChatTurn] = Field(default_factory=list)


class Citation(BaseModel):
    type: str
    id: str
    label: str


class CopilotUsage(BaseModel):
    input_tokens: int | None = None
    output_tokens: int | None = None


class CopilotResponse(BaseModel):
    incident_id: str
    question: str = ""
    answer: str = ""
    citations: list[Citation] = Field(default_factory=list)
    grounded: bool = False
    available: bool = True
    provider: str = ""
    model: str = ""
    generated_at: str = ""
    dropped_citations: int = 0
    usage: CopilotUsage | None = None
    error: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

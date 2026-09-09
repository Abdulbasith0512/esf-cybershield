"use client";

import { useState } from "react";
import { ApiError, askCopilot } from "@/lib/api-client";
import type { CopilotCitation, CopilotResponse } from "@/lib/types";

export const SUGGESTED_QUESTIONS: string[] = [
  "Summarize this incident",
  "Explain why this incident was created",
  "Walk me through the timeline",
  "What evidence supports this incident?",
  "What MITRE ATT&CK techniques are involved?",
  "What UEBA anomalies are relevant?",
  "What threat intelligence is available?",
  "What should I investigate next?",
];

function CitationChip({
  citation,
  onSelect,
}: {
  citation: CopilotCitation;
  onSelect?: (citation: CopilotCitation) => void;
}) {
  const interactive = onSelect && (citation.type === "detection" || citation.type === "event");
  const label = `${citation.type} ${citation.id}`;
  if (!interactive) {
    return (
      <span
        title={`${citation.label} — see the ${citation.type} section`}
        className="rounded border border-soc-border px-2 py-0.5 font-mono text-xs text-soc-muted"
      >
        {label}
      </span>
    );
  }
  return (
    <button
      type="button"
      title={`${citation.label} — highlight in evidence below`}
      onClick={() => onSelect(citation)}
      className="rounded border border-soc-accent/60 px-2 py-0.5 font-mono text-xs text-soc-accent underline"
    >
      {label}
    </button>
  );
}

/** AI-assisted incident Q&A. Read-only: renders grounded answers with
 *  evidence citations, never offers state-changing actions. */
export function CopilotSection({
  incidentId,
  evidenceByDetection,
  onFocusEvidence,
}: {
  incidentId: string;
  evidenceByDetection: Record<string, string[]>;
  onFocusEvidence: (eventIds: string[]) => void;
}) {
  const [question, setQuestion] = useState("");
  const [response, setResponse] = useState<CopilotResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(next: string) {
    const cleaned = next.trim();
    if (!cleaned || loading) return;
    setLoading(true);
    setError(null);
    try {
      const answer = await askCopilot(incidentId, cleaned);
      setResponse(answer);
    } catch (err) {
      setResponse(null);
      setError(
        err instanceof ApiError && err.status === 404
          ? "Incident not found."
          : err instanceof ApiError && err.status === 422
            ? "Enter a shorter non-empty question."
            : err instanceof ApiError && err.status === 503
              ? "Assistant unavailable — the AI provider is not configured or failed."
              : "Unable to reach the assistant.",
      );
    } finally {
      setLoading(false);
    }
  }

  function handleCitation(citation: CopilotCitation) {
    if (citation.type === "event") {
      onFocusEvidence([citation.id]);
    } else if (citation.type === "detection") {
      onFocusEvidence(evidenceByDetection[citation.id] ?? []);
    }
  }

  return (
    <div className="flex flex-col gap-3">
      <p className="text-xs text-soc-muted">
        AI-assisted analysis. Responses are grounded in the incident evidence provided to the
        Copilot. AI output is advisory and does not modify incident state.
      </p>
      <div className="flex flex-wrap gap-2">
        {SUGGESTED_QUESTIONS.map((suggested) => (
          <button
            key={suggested}
            type="button"
            disabled={loading}
            onClick={() => {
              setQuestion(suggested);
              void submit(suggested);
            }}
            className="rounded border border-soc-border px-2 py-1 text-xs text-soc-text hover:bg-soc-border/50 disabled:opacity-50"
          >
            {suggested}
          </button>
        ))}
      </div>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          void submit(question);
        }}
        className="flex flex-col gap-2"
      >
        <label htmlFor="copilot-question" className="text-xs uppercase tracking-wide text-soc-muted">
          Ask about this incident
        </label>
        <textarea
          id="copilot-question"
          value={question}
          onChange={(event) => setQuestion(event.target.value)}
          rows={2}
          maxLength={2000}
          placeholder="e.g. Why was this incident created?"
          className="rounded border border-soc-border bg-soc-bg p-2 text-sm text-soc-text"
        />
        <div>
          <button
            type="submit"
            disabled={loading || question.trim().length === 0}
            className="rounded border border-soc-accent/60 px-3 py-1 text-sm text-soc-accent disabled:opacity-50"
          >
            {loading ? "Asking…" : "Ask Copilot"}
          </button>
        </div>
      </form>
      {loading && <p className="text-sm text-soc-muted">Consulting incident evidence…</p>}
      {error && !loading && (
        <p role="alert" className="text-sm text-sev-high">
          {error}
        </p>
      )}
      {response && !loading && (
        <div className="flex flex-col gap-2 rounded border border-soc-border/60 p-2">
          <p className="font-mono text-xs text-soc-muted">
            {response.provider}/{response.model} · {response.generated_at}
          </p>
          {response.answer.split("\n").map((paragraph, index) => (
            <p key={index} className="text-sm leading-relaxed text-soc-text">
              {paragraph}
            </p>
          ))}
          {response.citations.length > 0 ? (
            <div className="flex flex-wrap gap-1.5">
              {response.citations.map((citation) => (
                <CitationChip
                  key={`${citation.type}:${citation.id}`}
                  citation={citation}
                  onSelect={handleCitation}
                />
              ))}
            </div>
          ) : (
            <p className="font-mono text-xs text-soc-muted">no evidence citations</p>
          )}
        </div>
      )}
    </div>
  );
}

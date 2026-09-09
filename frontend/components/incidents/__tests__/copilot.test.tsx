import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { CopilotSection, SUGGESTED_QUESTIONS } from "@/components/incidents/copilot-section";
import { ApiError } from "@/lib/api-client";
import type { CopilotResponse } from "@/lib/types";

const askCopilotMock = vi.fn();

vi.mock("@/lib/api-client", async (original) => ({
  ...(await original<typeof import("@/lib/api-client")>()),
  askCopilot: (...args: unknown[]) => askCopilotMock(...args),
}));

const answer: CopilotResponse = {
  incident_id: "inc-1",
  question: "Why was this incident created?",
  answer: "Incident 'T' groups 2 detection(s) [DET:det-1].",
  citations: [{ type: "detection", id: "det-1", label: "DET:det-1" }],
  grounded: true,
  available: true,
  provider: "fake",
  model: "fake-v1",
  generated_at: "2026-09-09T12:00:00+00:00",
  dropped_citations: 0,
  usage: null,
  error: null,
  metadata: {},
};

function renderSection(onFocus = vi.fn()) {
  return render(
    <CopilotSection
      incidentId="inc-1"
      evidenceByDetection={{ "det-1": ["e1", "e2"] }}
      onFocusEvidence={onFocus}
    />,
  );
}

describe("copilot section", () => {
  beforeEach(() => {
    askCopilotMock.mockReset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("renders the advisory notice and all suggested questions", () => {
    renderSection();
    expect(screen.getByText(/AI output is advisory/)).toBeInTheDocument();
    expect(screen.getByText(/grounded in the incident evidence/)).toBeInTheDocument();
    for (const suggested of SUGGESTED_QUESTIONS) {
      expect(screen.getByRole("button", { name: suggested })).toBeInTheDocument();
    }
  });

  it("submits a typed question and renders the response with citations", async () => {
    askCopilotMock.mockResolvedValue(answer);
    renderSection();
    fireEvent.change(screen.getByLabelText(/Ask about this incident/), {
      target: { value: "Why was this incident created?" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Ask Copilot" }));
    expect(screen.getByText(/Consulting incident evidence/)).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText(/groups 2 detection/)).toBeInTheDocument());
    expect(screen.getByText("detection det-1")).toBeInTheDocument();
    expect(screen.getByText(/fake\/fake-v1/)).toBeInTheDocument();
    expect(askCopilotMock).toHaveBeenCalledWith("inc-1", "Why was this incident created?");
  });

  it("shows the unavailable state when the provider is down", async () => {
    askCopilotMock.mockRejectedValue(new ApiError(503, { detail: "assistant unavailable" }));
    renderSection();
    fireEvent.change(screen.getByLabelText(/Ask about this incident/), {
      target: { value: "Summarize this incident" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Ask Copilot" }));
    await waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent(/Assistant unavailable/),
    );
  });

  it("focuses evidence when a detection citation is clicked", async () => {
    askCopilotMock.mockResolvedValue(answer);
    const onFocus = vi.fn();
    renderSection(onFocus);
    fireEvent.click(screen.getByRole("button", { name: "Summarize this incident" }));
    await waitFor(() => expect(screen.getByText("detection det-1")).toBeInTheDocument());
    fireEvent.click(screen.getByText("detection det-1"));
    expect(onFocus).toHaveBeenCalledWith(["e1", "e2"]);
  });
});

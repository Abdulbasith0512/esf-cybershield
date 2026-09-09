import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { CaseSection } from "@/components/incidents/case-section";
import type { InvestigationCase } from "@/lib/types";

const baseCase: InvestigationCase = {
  status: "INVESTIGATING",
  assignee: null,
  assigned_at: null,
  allowed_transitions: ["CONTAINED", "RESOLVED"],
  notes: [],
  activity: [],
};

describe("case section", () => {
  beforeEach(() => {
    process.env.NEXT_PUBLIC_API_BASE_URL = "http://localhost:8000";
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("offers only allowed status transitions", () => {
    render(<CaseSection incidentId="a" caseState={baseCase} onChanged={() => {}} />);
    const select = screen.getByLabelText(/Transition to/);
    expect(select).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "CONTAINED" })).toBeInTheDocument();
    expect(screen.queryByRole("option", { name: "NEW" })).not.toBeInTheDocument();
  });

  it("shows assignee state and unassign only when assigned", () => {
    const { rerender } = render(<CaseSection incidentId="a" caseState={baseCase} onChanged={() => {}} />);
    expect(screen.getByText("Unassigned")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Unassign" })).not.toBeInTheDocument();
    rerender(<CaseSection incidentId="a" caseState={{ ...baseCase, assignee: "zoe" }} onChanged={() => {}} />);
    expect(screen.getByText("zoe")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Unassign" })).toBeInTheDocument();
  });

  it("renders notes and activity in order", () => {
    render(
      <CaseSection
        incidentId="a"
        caseState={{
          ...baseCase,
          notes: [
            { note_id: "n1", author: "zoe", body: "first", created_at: "2026-09-05T09:00:00Z" },
            { note_id: "n2", author: null, body: "second", created_at: "2026-09-05T09:01:00Z" },
          ],
          activity: [
            { activity_id: "a1", action: "ASSIGNED", actor: "zoe", created_at: "2026-09-05T09:00:00Z", metadata: {} },
            { activity_id: "a2", action: "NOTE_ADDED", actor: null, created_at: "2026-09-05T09:01:00Z", metadata: {} },
          ],
        }}
        onChanged={() => {}}
      />,
    );
    expect(screen.getByText("first")).toBeInTheDocument();
    expect(screen.getByText(/anonymous/)).toBeInTheDocument();
    expect(screen.getByText(/ASSIGNED/)).toBeInTheDocument();
    expect(screen.getByText(/NOTE_ADDED/)).toBeInTheDocument();
  });

  it("shows empty states when nothing recorded", () => {
    render(<CaseSection incidentId="a" caseState={baseCase} onChanged={() => {}} />);
    expect(screen.getByText("No analyst notes yet.")).toBeInTheDocument();
    expect(screen.getByText("No recorded case activity yet.")).toBeInTheDocument();
  });

  it("marks terminal states with no transitions", () => {
    render(
      <CaseSection
        incidentId="a"
        caseState={{ ...baseCase, status: "RESOLVED", allowed_transitions: [] }}
        onChanged={() => {}}
      />,
    );
    expect(screen.getByText(/terminal state/)).toBeInTheDocument();
  });

  it("handles missing case state", () => {
    render(<CaseSection incidentId="a" caseState={null} onChanged={() => {}} />);
    expect(screen.getByText("Case state unavailable for this incident.")).toBeInTheDocument();
  });

  it("submits a note and refreshes", async () => {
    const onChanged = vi.fn();
    global.fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ note_id: "n9", incident_id: "a", author: null, body: "hi", created_at: "2026-09-05T09:02:00Z" }), { status: 201 }),
    ) as unknown as typeof fetch;
    render(<CaseSection incidentId="a" caseState={baseCase} onChanged={onChanged} />);
    fireEvent.change(screen.getByPlaceholderText(/Add an analyst note/), { target: { value: "hi" } });
    fireEvent.click(screen.getByRole("button", { name: "Add note" }));
    await waitFor(() => expect(onChanged).toHaveBeenCalledTimes(1));
    vi.unstubAllGlobals();
  });
});

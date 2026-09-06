import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import IncidentsPage from "@/app/incidents/page";
import type { IncidentSummary } from "@/lib/types";

const row: IncidentSummary = {
  incident_id: "1125cb0a-1841-534e-95cf-3377c12d803d",
  title: "Potential Credential Compromise with Suspicious Data Transfer",
  severity: "CRITICAL",
  status: "OPEN",
  confidence: 1.0,
  risk_score: 100,
  risk_band: "CRITICAL",
  ueba_available: true,
  ueba_anomaly_score: 1.0,
  ueba_anomaly_flag: true,
  first_seen: "2026-09-05T08:50:05+00:00",
  last_seen: "2026-09-05T09:19:31+00:00",
};

function pageOf(items: IncidentSummary[], total = items.length) {
  return { items, page: 1, page_size: 25, total, pages: 1 };
}

describe("incidents queue", () => {
  beforeEach(() => {
    process.env.NEXT_PUBLIC_API_BASE_URL = "http://localhost:8000";
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("renders live incident rows with severity and UEBA state", async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(JSON.stringify(pageOf([row])), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    render(<IncidentsPage />);
    await waitFor(() => expect(screen.getByText(row.title)).toBeInTheDocument());
    expect(screen.getByRole("img", { name: "severity CRITICAL" })).toBeInTheDocument();
    expect(screen.getByText("Flagged")).toBeInTheDocument();
    expect(screen.queryByText(/backend endpoint not available/)).not.toBeInTheDocument();
  });

  it("shows empty state when the queue is empty, not zero-fabrication", async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(JSON.stringify(pageOf([])), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    render(<IncidentsPage />);
    await waitFor(() => expect(screen.getByText("No incidents available.")).toBeInTheDocument());
  });

  it("shows error state on API failure, never a fake zero", async () => {
    vi.mocked(fetch).mockRejectedValue(new TypeError("fetch failed"));
    render(<IncidentsPage />);
    await waitFor(() =>
      expect(screen.getByText("Unable to load incidents.")).toBeInTheDocument(),
    );
    expect(screen.queryByText("No incidents available.")).not.toBeInTheDocument();
  });
});

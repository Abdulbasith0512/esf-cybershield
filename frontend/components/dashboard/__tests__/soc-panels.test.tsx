import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { HighestRisk } from "@/components/dashboard/highest-risk";
import { SeverityDistribution } from "@/components/dashboard/severity-distribution";

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

const row = {
  incident_id: "inc-9",
  title: "Risky incident",
  severity: "CRITICAL",
  status: "OPEN",
  confidence: 1.0,
  risk_score: 100,
  risk_band: "CRITICAL",
  ueba_available: false,
  ueba_anomaly_score: null,
  ueba_anomaly_flag: null,
  first_seen: "2026-09-05T08:00:00+00:00",
  last_seen: "2026-09-05T09:00:00+00:00",
};

describe("dashboard soc panels", () => {
  beforeEach(() => {
    process.env.NEXT_PUBLIC_API_BASE_URL = "http://localhost:8000";
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("renders severity totals from the list API, never invented deltas", async () => {
    vi.mocked(fetch).mockImplementation((input) => {
      const url = String(input);
      const total = url.includes("severity=CRITICAL") ? 2 : 0;
      return Promise.resolve(
        jsonResponse({ items: [], page: 1, page_size: 1, total, pages: 1 }),
      );
    });
    render(<SeverityDistribution />);
    await waitFor(() => expect(screen.getByText("2")).toBeInTheDocument());
    expect(screen.getByRole("img", { name: "severity CRITICAL" })).toBeInTheDocument();
    expect(screen.queryByText(/vs last week|uptime|analysts/i)).not.toBeInTheDocument();
  });

  it("renders the highest-risk recent incidents with links", async () => {
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse({ items: [row], page: 1, page_size: 25, total: 1, pages: 1 }),
    );
    render(<HighestRisk />);
    await waitFor(() => expect(screen.getByText("Risky incident")).toBeInTheDocument());
    expect(screen.getByText(/risk 100 · CRITICAL/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Risky incident" })).toHaveAttribute(
      "href",
      "/incidents/inc-9",
    );
  });

  it("shows honest empty states when there is no data", async () => {
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse({ items: [], page: 1, page_size: 25, total: 0, pages: 1 }),
    );
    render(<HighestRisk />);
    await waitFor(() =>
      expect(screen.getByText("No incidents available.")).toBeInTheDocument(),
    );
  });
});

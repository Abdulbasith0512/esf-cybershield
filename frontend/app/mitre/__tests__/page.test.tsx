import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import MitrePage from "@/app/mitre/page";
import type { IncidentDetail, IncidentSummary } from "@/lib/types";

const summary: IncidentSummary = {
  incident_id: "inc-1",
  title: "T",
  severity: "HIGH",
  status: "OPEN",
  confidence: 0.9,
  risk_score: 60,
  risk_band: "HIGH",
  ueba_available: false,
  ueba_anomaly_score: null,
  ueba_anomaly_flag: null,
  first_seen: "2026-09-05T08:00:00+00:00",
  last_seen: "2026-09-05T09:00:00+00:00",
};

const detail: IncidentDetail = {
  ...summary,
  reason: "r",
  risk_explanation: "e",
  detection_ids: ["det-a", "det-b"],
  evidence_event_ids: ["evt-1"],
  incident_metadata: {},
  mitre_techniques: [
    {
      technique_id: "T1110",
      technique_name: "Brute Force",
      tactic: "Credential Access",
      source_rule_id: "AUTH-001",
      rationale: "r",
      confidence: 0.85,
      catalog_version: "v1",
    },
  ],
  risk_breakdown: null,
  ueba_evidence: null,
  created_at: "2026-09-05T09:00:00+00:00",
  updated_at: "2026-09-05T09:00:00+00:00",
};

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function mockApi(detailBody: IncidentDetail) {
  vi.mocked(fetch).mockImplementation((input) => {
    const url = String(input);
    if (url.includes("/api/v1/incidents?") || url.endsWith("/api/v1/incidents")) {
      return Promise.resolve(
        jsonResponse({ items: [summary], page: 1, page_size: 100, total: 1, pages: 1 }),
      );
    }
    return Promise.resolve(jsonResponse(detailBody));
  });
}

describe("mitre page", () => {
  beforeEach(() => {
    process.env.NEXT_PUBLIC_API_BASE_URL = "http://localhost:8000";
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("renders mapped techniques with traceable counts", async () => {
    mockApi(detail);
    render(<MitrePage />);
    await waitFor(() => expect(screen.getByText("T1110")).toBeInTheDocument());
    expect(screen.getByText("Brute Force")).toBeInTheDocument();
    expect(screen.getByText(/via AUTH-001/)).toBeInTheDocument();
    expect(screen.getByText(/Detections: 2/)).toBeInTheDocument();
    expect(screen.queryByText(/backend endpoint not available/)).not.toBeInTheDocument();
  });

  it("renders only stored techniques and an honest empty state", async () => {
    mockApi({ ...detail, mitre_techniques: [] });
    render(<MitrePage />);
    await waitFor(() =>
      expect(screen.getByText("No MITRE techniques mapped yet.")).toBeInTheDocument(),
    );
    expect(screen.queryByText("T1110")).not.toBeInTheDocument();
  });

  it("shows an error state on API failure", async () => {
    vi.mocked(fetch).mockRejectedValue(new TypeError("fetch failed"));
    render(<MitrePage />);
    await waitFor(() =>
      expect(screen.getByText("Unable to load MITRE coverage.")).toBeInTheDocument(),
    );
  });
});

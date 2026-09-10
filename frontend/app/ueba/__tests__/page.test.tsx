import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import UebaPage from "@/app/ueba/page";
import type { IncidentDetail, IncidentSummary } from "@/lib/types";

const summary: IncidentSummary = {
  incident_id: "inc-1",
  title: "T",
  severity: "HIGH",
  status: "OPEN",
  confidence: 0.9,
  risk_score: 60,
  risk_band: "HIGH",
  ueba_available: true,
  ueba_anomaly_score: 0.9,
  ueba_anomaly_flag: true,
  first_seen: "2026-09-05T08:00:00+00:00",
  last_seen: "2026-09-05T09:00:00+00:00",
};

const detail: IncidentDetail = {
  ...summary,
  reason: "r",
  risk_explanation: "e",
  detection_ids: ["det-a"],
  evidence_event_ids: ["evt-1"],
  incident_metadata: {},
  mitre_techniques: [],
  risk_breakdown: null,
  ueba_evidence: {
    incident_id: "inc-1",
    incident_fingerprint: "fp",
    available: true,
    anomaly_score: 0.9,
    anomaly_flag: true,
    model_version: "m1",
    feature_version: null,
    feature_window_start: null,
    feature_window_end: null,
    observations: [
      {
        entity_key: "user:alice",
        observation_time: "2026-09-05T08:30:00+00:00",
        anomaly_score: 0.9,
        anomaly_flag: true,
        baseline_status: "established",
        feature_context: {},
        event_overlap: [],
      },
    ],
    reason: "r",
    metadata: {},
  },
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

describe("ueba page", () => {
  beforeEach(() => {
    process.env.NEXT_PUBLIC_API_BASE_URL = "http://localhost:8000";
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("renders stored anomaly scores verbatim", async () => {
    mockApi(detail);
    render(<UebaPage />);
    await waitFor(() => expect(screen.getByText("user:alice")).toBeInTheDocument());
    expect(screen.getByText(/score 0\.90/)).toBeInTheDocument();
    expect(screen.getByText(/flagged/)).toBeInTheDocument();
    expect(screen.queryByText(/backend endpoint not available/)).not.toBeInTheDocument();
  });

  it("shows an honest empty state when nothing is recorded", async () => {
    mockApi({ ...detail, ueba_evidence: null });
    render(<UebaPage />);
    await waitFor(() =>
      expect(screen.getByText("No UEBA anomalies recorded yet.")).toBeInTheDocument(),
    );
    expect(screen.queryByText("user:alice")).not.toBeInTheDocument();
  });

  it("shows an error state on API failure", async () => {
    vi.mocked(fetch).mockRejectedValue(new TypeError("fetch failed"));
    render(<UebaPage />);
    await waitFor(() =>
      expect(screen.getByText("Unable to load UEBA anomalies.")).toBeInTheDocument(),
    );
  });
});

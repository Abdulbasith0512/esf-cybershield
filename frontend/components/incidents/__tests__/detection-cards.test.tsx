import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { renderHook, waitFor } from "@testing-library/react";
import { DetectionCards } from "@/components/incidents/detection-cards";
import { useIncidentDetections } from "@/lib/use-incident-detections";
import type { DetectionDetail } from "@/lib/types";

const det: DetectionDetail = {
  detection_id: "det-auth-1",
  rule_id: "AUTH-001",
  rule_name: "Brute Force Followed by Successful Authentication",
  severity: "HIGH",
  confidence: 0.92,
  reason: "Multiple failed authentications followed by a successful login.",
  evidence_event_ids: ["evt-1", "evt-2", "evt-3", "evt-4"],
  first_seen: "2026-09-05T08:50:05+00:00",
  last_seen: "2026-09-05T08:52:31+00:00",
  detection_metadata: { user: "user_037", fail_count: 3 },
  created_at: "2026-09-05T09:20:00+00:00",
  updated_at: "2026-09-05T09:20:00+00:00",
};

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("detection cards", () => {
  beforeEach(() => {
    process.env.NEXT_PUBLIC_API_BASE_URL = "http://localhost:8000";
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("renders rule name, severity, confidence, and evidence count", () => {
    render(<DetectionCards items={[det]} failed={[]} />);
    expect(screen.getByText("AUTH-001")).toBeInTheDocument();
    expect(screen.getByText("Brute Force Followed by Successful Authentication")).toBeInTheDocument();
    expect(screen.getByRole("img", { name: "severity HIGH" })).toBeInTheDocument();
    expect(screen.getByText(/conf 0.92/)).toBeInTheDocument();
    expect(screen.getByText(/4 events/)).toBeInTheDocument();
  });

  it("expands to reason, window, and evidence IDs", () => {
    render(<DetectionCards items={[det]} failed={[]} onFocusEvidence={() => {}} />);
    fireEvent.click(screen.getByRole("button", { expanded: false }));
    expect(screen.getByText("Multiple failed authentications followed by a successful login.")).toBeInTheDocument();
    expect(screen.getByText("evt-3")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /view evidence/i })).toBeInTheDocument();
  });

  it("shows failure banner without destroying loaded cards", () => {
    render(<DetectionCards items={[det]} failed={[{ detectionId: "det-x", status: 404 }]} />);
    expect(screen.getByText("Detection details unavailable.")).toBeInTheDocument();
    expect(screen.getByText("AUTH-001")).toBeInTheDocument();
  });

  it("renders empty state when no detections", () => {
    render(<DetectionCards items={[]} failed={[]} />);
    expect(screen.getByText("No detections attached to this incident.")).toBeInTheDocument();
  });
});

describe("useIncidentDetections", () => {
  beforeEach(() => {
    process.env.NEXT_PUBLIC_API_BASE_URL = "http://localhost:8000";
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("hydrates detections and tolerates one 404", async () => {
    vi.mocked(fetch).mockImplementation((url) => {
      const u = String(url);
      if (u.endsWith("/det-auth-1")) return Promise.resolve(jsonResponse(det));
      return Promise.resolve(jsonResponse({ detail: "detection not found" }, 404));
    });
    const { result } = renderHook(() => useIncidentDetections(["det-auth-1", "det-missing"]));
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.items.map((d) => d.detection_id)).toEqual(["det-auth-1"]);
    expect(result.current.failed).toEqual([{ detectionId: "det-missing", status: 404 }]);
    expect(fetch).toHaveBeenCalledTimes(2);
  });
});

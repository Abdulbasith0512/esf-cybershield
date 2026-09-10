import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import DetectionRulesPage from "@/app/detection-rules/page";
import type { DetectionSummary } from "@/lib/types";

const det: DetectionSummary = {
  detection_id: "det-a",
  rule_id: "AUTH-001",
  rule_name: "Auth rule",
  severity: "HIGH",
  confidence: 0.8,
  first_seen: "2026-09-05T08:00:00+00:00",
  last_seen: "2026-09-05T08:05:00+00:00",
  reason: "brute force pattern",
};

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("detection rules page", () => {
  beforeEach(() => {
    process.env.NEXT_PUBLIC_API_BASE_URL = "http://localhost:8000";
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("renders real rule data and never the unavailable placeholder", async () => {
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse({ items: [det], page: 1, page_size: 100, total: 1, pages: 1 }),
    );
    render(<DetectionRulesPage />);
    await waitFor(() => expect(screen.getByText("AUTH-001")).toBeInTheDocument());
    expect(screen.getByText("Auth rule")).toBeInTheDocument();
    expect(screen.getByText(/1 firing/)).toBeInTheDocument();
    expect(screen.getByText("brute force pattern")).toBeInTheDocument();
    expect(screen.queryByText(/backend endpoint not available/)).not.toBeInTheDocument();
  });

  it("shows an honest empty state when nothing fired", async () => {
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse({ items: [], page: 1, page_size: 100, total: 0, pages: 1 }),
    );
    render(<DetectionRulesPage />);
    await waitFor(() =>
      expect(screen.getByText("No persisted detections yet.")).toBeInTheDocument(),
    );
  });

  it("shows an error state with retry on API failure", async () => {
    vi.mocked(fetch).mockRejectedValue(new TypeError("fetch failed"));
    render(<DetectionRulesPage />);
    await waitFor(() =>
      expect(screen.getByText("Unable to load detection rules.")).toBeInTheDocument(),
    );
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();
    vi.mocked(fetch).mockResolvedValue(
      jsonResponse({ items: [det], page: 1, page_size: 100, total: 1, pages: 1 }),
    );
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    await waitFor(() => expect(screen.getByText("AUTH-001")).toBeInTheDocument());
  });
});

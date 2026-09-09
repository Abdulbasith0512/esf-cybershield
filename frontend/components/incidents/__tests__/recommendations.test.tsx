import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { RecommendationsList } from "@/components/incidents/recommendations-section";
import type { Recommendation } from "@/lib/types";

const recs: Recommendation[] = [
  {
    id: "rec-triage",
    priority: "HIGH",
    category: "TRIAGE",
    title: "Triage the incident timeline",
    reason: "Incident 'T' groups 2 detection(s).",
    actions: ["Review the ordered detection timeline from earliest to latest."],
    evidence_refs: {
      detection_ids: ["det-1", "det-2"],
      detection_count: 2,
      evidence_event_ids: ["det-1-e1"],
      evidence_count: 1,
    },
  },
  {
    id: "rec-network-FLOW-001",
    priority: "MEDIUM",
    category: "NETWORK",
    title: "Investigate high connection-rate activity",
    reason: "1 FLOW-001 detection(s) observed.",
    actions: ["Identify the dominant source and destination endpoints."],
    evidence_refs: {
      detection_ids: ["det-1"],
      detection_count: 1,
      evidence_event_ids: [],
      evidence_count: 0,
    },
  },
];

describe("recommendations list", () => {
  it("renders priorities, titles, actions, and the advisory notice", () => {
    render(<RecommendationsList recommendations={recs} />);
    expect(screen.getByText(/Advisory only/)).toBeInTheDocument();
    expect(screen.getByText("Triage the incident timeline")).toBeInTheDocument();
    expect(screen.getByText("Investigate high connection-rate activity")).toBeInTheDocument();
    expect(screen.getByText(/Review the ordered detection timeline/)).toBeInTheDocument();
    expect(screen.getByText("HIGH")).toBeInTheDocument();
    expect(screen.getByText("MEDIUM")).toBeInTheDocument();
    expect(screen.getByText(/2 detections: det-1, det-2/)).toBeInTheDocument();
  });

  it("renders an empty state when there are no recommendations", () => {
    render(<RecommendationsList recommendations={[]} />);
    expect(screen.getByText("No recommendations for this incident.")).toBeInTheDocument();
  });
});

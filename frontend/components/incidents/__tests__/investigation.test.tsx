import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { EntitySummary } from "@/components/incidents/entity-summary";
import { ExplanationCard } from "@/components/incidents/explanation-card";
import type { InvestigationEntities, InvestigationExplanation } from "@/lib/types";

const explanation: InvestigationExplanation = {
  summary: "Incident 'T' (HIGH) groups 2 detection(s).",
  trigger_detections: ["det-1", "det-2"],
  correlation_reason: "Linked by shared entity user 'alice'.",
  risk_factors: [{ factor: "incident severity", points: 10 }],
  mitre_context: [{ technique_id: "T1078", rule_ids: ["AUTH-001"] }],
  ueba_context: { available: false },
  unavailable: ["UEBA evidence"],
};

const entities: InvestigationEntities = {
  source_ips: ["10.0.0.5"],
  destination_ips: [],
  ports: [443],
  protocols: ["TCP"],
  users: ["alice"],
  hosts: [],
  processes: [],
};

describe("explanation card", () => {
  it("renders summary, correlation reason, factors, and unavailable markers", () => {
    render(<ExplanationCard explanation={explanation} />);
    expect(screen.getByText(/groups 2 detection/)).toBeInTheDocument();
    expect(screen.getByText(/shared entity user/)).toBeInTheDocument();
    expect(screen.getByText(/incident severity/)).toBeInTheDocument();
    expect(screen.getByText(/det-1, det-2/)).toBeInTheDocument();
    expect(screen.getByText(/UEBA evidence/)).toBeInTheDocument();
  });
});

describe("entity summary", () => {
  it("renders present entities and marks missing ones unavailable", () => {
    render(<EntitySummary entities={entities} />);
    expect(screen.getByText("10.0.0.5")).toBeInTheDocument();
    expect(screen.getByText("alice")).toBeInTheDocument();
    expect(screen.getAllByText("Not available")).toHaveLength(3);
  });
});

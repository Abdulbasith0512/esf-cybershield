import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { ClassificationBadge, ThreatIntelList } from "@/components/incidents/threat-intel-section";
import type { EnrichedObservable } from "@/lib/types";

function item(overrides: Partial<EnrichedObservable> = {}): EnrichedObservable {
  return {
    observable: {
      type: "ipv4",
      value: "198.51.100.23",
      normalized_value: "198.51.100.23",
      source: "destination_ip",
      first_seen: "2026-09-03T09:00:00",
      last_seen: "2026-09-03T09:01:00",
      event_count: 2,
      event_ids: ["e1", "e2"],
    },
    available: true,
    intelligence: {
      provider: "local-test",
      observable_type: "ipv4",
      observable_value: "198.51.100.23",
      classification: "malicious",
      confidence: 1,
      categories: ["test-fixture"],
      first_seen: null,
      last_seen: null,
      reference: "RFC 5737 TEST-NET-2",
      retrieved_at: "2026-09-09T12:00:00+00:00",
      metadata: {},
    },
    error: null,
    detection_ids: ["det-1"],
    incident_id: "inc-1",
    ...overrides,
  };
}

describe("threat intel list", () => {
  it("renders observable, classification, provider attribution, and counts", () => {
    render(<ThreatIntelList items={[item()]} provider="local-test" />);
    expect(screen.getByText("198.51.100.23")).toBeInTheDocument();
    expect(screen.getByText("Malicious")).toBeInTheDocument();
    expect(screen.getByText(/Source: local-test/)).toBeInTheDocument();
    expect(screen.getByText(/test intelligence/)).toBeInTheDocument();
    expect(screen.getByText(/2 events/)).toBeInTheDocument();
    expect(screen.getByText(/det-1/)).toBeInTheDocument();
  });

  it("renders all classification states", () => {
    render(<ClassificationBadge classification="malicious" />);
    render(<ClassificationBadge classification="suspicious" />);
    render(<ClassificationBadge classification="benign" />);
    render(<ClassificationBadge classification="unknown" />);
    render(<ClassificationBadge classification="unavailable" />);
    expect(screen.getByText("Malicious")).toBeInTheDocument();
    expect(screen.getByText("Suspicious")).toBeInTheDocument();
    expect(screen.getByText("Benign")).toBeInTheDocument();
    expect(screen.getByText("Unknown")).toBeInTheDocument();
    expect(screen.getByText("Unavailable")).toBeInTheDocument();
  });

  it("renders unknown and unavailable states explicitly", () => {
    const unknown = item({
      available: true,
      intelligence: { ...item().intelligence!, classification: "unknown", confidence: 0 },
    });
    const down = item({ available: false, intelligence: null, error: "boom lookup failed" });
    render(<ThreatIntelList items={[unknown, down]} provider="local-test" />);
    expect(screen.getByText("Unknown")).toBeInTheDocument();
    expect(screen.getByText("Unavailable")).toBeInTheDocument();
    expect(screen.getByText(/boom lookup failed/)).toBeInTheDocument();
  });

  it("renders an empty state when there are no observables", () => {
    render(<ThreatIntelList items={[]} provider="local-test" />);
    expect(screen.getByText("No observables extracted for this incident.")).toBeInTheDocument();
  });
});

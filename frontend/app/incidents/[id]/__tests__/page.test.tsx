import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { IncidentDetailView } from "@/app/incidents/[id]/page";
import { sortEvidenceEvents } from "@/lib/use-incident-evidence";
import { InvestigationTimeline } from "@/components/incidents/investigation-timeline";
import { RiskBreakdownView } from "@/components/incidents/risk-breakdown";
import { UebaObservations } from "@/components/incidents/ueba-observations";
import { IncidentContext } from "@/components/incidents/incident-context";
import { AttackStory } from "@/components/incidents/attack-story";
import type { IncidentDetail, SecurityEvent } from "@/lib/types";

function evt(overrides: Partial<SecurityEvent> & { event_id: string }): SecurityEvent {
  return {
    id: `id-${overrides.event_id}`,
    timestamp: "2026-09-05T09:00:00Z",
    event_type: "authentication",
    source: "windows",
    host: "WIN-019",
    user: "user_037",
    source_ip: "192.168.50.11",
    destination_ip: null,
    destination_port: null,
    protocol: null,
    process_name: null,
    parent_process: null,
    command_line: null,
    file_hash: null,
    domain: null,
    url: null,
    bytes_sent: null,
    bytes_received: null,
    status: "failed",
    raw_event: {},
    created_at: "2026-09-05T09:00:01Z",
    ...overrides,
  };
}

const baseIncident = {
  incident_id: "1125cb0a",
  title: "Potential Credential Compromise",
  severity: "CRITICAL",
  status: "OPEN",
  confidence: 1.0,
  reason: "Correlated 9 detections within the correlation window.",
  risk_score: 100,
  risk_band: "CRITICAL",
  risk_explanation: "Risk 100 (CRITICAL) is elevated.",
  first_seen: "2026-09-05T08:50:05+00:00",
  last_seen: "2026-09-05T09:19:31+00:00",
  detection_ids: ["det-auth", "det-proc"],
  evidence_event_ids: ["evt-1", "evt-2"],
  incident_metadata: {
    user: "user_037",
    host: "WIN-019",
    rule_ids: ["AUTH-001", "PROC-001"],
    sequence_hits: [["AUTH-001", "PROC-001"]],
  },
  mitre_techniques: [
    {
      technique_id: "T1110",
      technique_name: "Brute Force",
      tactic: "Credential Access",
      source_rule_id: "AUTH-001",
      rationale: "Fails then success.",
      confidence: 0.85,
      catalog_version: "project-static-v1",
    },
  ],
  risk_breakdown: {
    severity_points: 60,
    diversity_points: 16,
    confidence_points: 8,
    evidence_points: 2,
    sequence_points: 0,
    mitre_points: 6,
    contextual_points: 0,
    total: 92,
  },
  ueba_evidence: {
    incident_id: "1125cb0a",
    incident_fingerprint: "incident:det-auth,det-proc",
    available: true,
    anomaly_score: 1.0,
    anomaly_flag: true,
    model_version: "ueba-iforest-v1",
    feature_version: "ueba-features-v1",
    feature_window_start: "2026-09-05T08:50:05+00:00",
    feature_window_end: "2026-09-05T09:19:31+00:00",
    observations: [
      {
        entity_key: "user_037",
        observation_time: "2026-09-05T09:00:00+00:00",
        anomaly_score: 1.0,
        anomaly_flag: true,
        baseline_status: "READY",
        feature_context: { failed_auth_count: 3, outbound_bytes_log1p: 22.2 },
        event_overlap: ["evt-1"],
      },
    ],
    reason: "UEBA behavioral anomaly evidence.",
    metadata: {},
  },
  created_at: "2026-09-05T09:20:00+00:00",
  updated_at: "2026-09-05T09:20:00+00:00",
} satisfies IncidentDetail;

describe("timeline ordering", () => {
  it("sorts chronologically with event_id tiebreak, ignoring arrival order", () => {
    const shuffled = [
      evt({ event_id: "evt-c", timestamp: "2026-09-05T09:19:31Z" }),
      evt({ event_id: "evt-a", timestamp: "2026-09-05T08:50:05Z" }),
      evt({ event_id: "evt-b", timestamp: "2026-09-05T08:50:05Z" }),
    ];
    const sorted = sortEvidenceEvents(shuffled);
    expect(sorted.map((e) => e.event_id)).toEqual(["evt-a", "evt-b", "evt-c"]);
  });

  it("renders timeline rows in chronological order", () => {
    render(
      <InvestigationTimeline
        events={[
          evt({ event_id: "evt-2", timestamp: "2026-09-05T09:19:31Z", event_type: "data_transfer" }),
          evt({ event_id: "evt-1", timestamp: "2026-09-05T08:50:05Z" }),
        ]}
        firstSeen="2026-09-05T08:50:05+00:00"
        lastSeen="2026-09-05T09:19:31+00:00"
      />,
    );
    const items = screen.getAllByRole("listitem");
    expect(items[0]).toHaveTextContent("authentication");
    expect(items[1]).toHaveTextContent("data_transfer");
  });

  it("shows empty state when no evidence events", () => {
    render(<InvestigationTimeline events={[]} firstSeen="2026-09-05T08:50:05+00:00" lastSeen="2026-09-05T09:19:31+00:00" />);
    expect(screen.getByText("No evidence events associated with this incident.")).toBeInTheDocument();
  });
});

describe("risk and UEBA rendering", () => {
  it("renders persisted breakdown terms and explanation verbatim", () => {
    render(<RiskBreakdownView breakdown={baseIncident.risk_breakdown} explanation={baseIncident.risk_explanation} />);
    expect(screen.getByText("Severity")).toBeInTheDocument();
    expect(screen.getByText("60")).toBeInTheDocument();
    expect(screen.getByText("Risk 100 (CRITICAL) is elevated.")).toBeInTheDocument();
  });

  it("renders UEBA anomalous state with score and model", () => {
    render(<UebaObservations ueba={baseIncident.ueba_evidence} />);
    expect(screen.getByRole("img", { name: "anomalous behavior" })).toBeInTheDocument();
    expect(screen.getByText(/ueba-iforest-v1/)).toBeInTheDocument();
    expect(screen.getByText(/failed_auth_count/)).toBeInTheDocument();
  });

  it("renders UEBA unavailable honestly", () => {
    render(<UebaObservations ueba={{ ...baseIncident.ueba_evidence, available: false }} />);
    expect(screen.getByText("UEBA evidence unavailable for this incident.")).toBeInTheDocument();
    expect(screen.queryByText(/ANOMALOUS/)).not.toBeInTheDocument();
  });

  it("renders UEBA null as unavailable, not zero", () => {
    render(<UebaObservations ueba={null} />);
    expect(screen.getByText("UEBA evidence unavailable for this incident.")).toBeInTheDocument();
  });
});

describe("context and story", () => {
  it("shows only actual metadata values", () => {
    render(<IncidentContext incident={baseIncident} />);
    expect(screen.getByText("user_037")).toBeInTheDocument();
    expect(screen.getByText("WIN-019")).toBeInTheDocument();
    expect(screen.queryByText(/Attacker IP/)).not.toBeInTheDocument();
  });

  it("derives story stages only from present evidence", () => {
    const events = [
      evt({ event_id: "evt-1", timestamp: "2026-09-05T08:50:05Z", event_type: "authentication", status: "failed" }),
      evt({ event_id: "evt-2", timestamp: "2026-09-05T09:16:15Z", event_type: "process_creation", process_name: "powershell.exe" }),
    ];
    render(<AttackStory incident={{ ...baseIncident, evidence_event_ids: ["evt-1", "evt-2"] }} events={events} />);
    expect(screen.getByText("Authentication anomalies")).toBeInTheDocument();
    expect(screen.getByText("Suspicious process execution")).toBeInTheDocument();
    expect(screen.queryByText("Large outbound transfer")).not.toBeInTheDocument();
  });

  it("shows empty story when nothing matches", () => {
    render(<AttackStory incident={baseIncident} events={[]} />);
    expect(screen.getByText(/No staged attack story/)).toBeInTheDocument();
  });
});

describe("detail page states", () => {
  beforeEach(() => {
    process.env.NEXT_PUBLIC_API_BASE_URL = "http://localhost:8000";
    vi.stubGlobal("fetch", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("renders 404 distinctly from generic errors", async () => {
    vi.mocked(fetch).mockResolvedValue(
      new Response(JSON.stringify({ detail: "incident not found" }), { status: 404 }),
    );
    render(<IncidentDetailView id="missing" />);
    await screen.findByText("Incident not found.");
  });

  it("renders error state on API failure, never empty-evidence text", async () => {
    vi.mocked(fetch).mockRejectedValue(new TypeError("fetch failed"));
    render(<IncidentDetailView id="any" />);
    await screen.findByText("Unable to load incident.");
    expect(screen.queryByText("No evidence events associated with this incident.")).not.toBeInTheDocument();
  });
});

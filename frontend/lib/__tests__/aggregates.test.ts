import { describe, expect, it } from "vitest";
import { aggregateAnomalies, aggregateRules, aggregateTechniques } from "@/lib/aggregates";
import type { DetectionSummary, IncidentDetail } from "@/lib/types";

const detA: DetectionSummary = {
  detection_id: "det-a",
  rule_id: "AUTH-001",
  rule_name: "Auth rule",
  severity: "HIGH",
  confidence: 0.8,
  first_seen: "2026-09-05T08:00:00+00:00",
  last_seen: "2026-09-05T08:05:00+00:00",
  reason: "brute force pattern",
};

const detB: DetectionSummary = {
  detection_id: "det-b",
  rule_id: "AUTH-001",
  rule_name: "Auth rule",
  severity: "MEDIUM",
  confidence: 0.6,
  first_seen: "2026-09-05T09:00:00+00:00",
  last_seen: "2026-09-05T09:05:00+00:00",
  reason: "brute force pattern",
};

function incident(partial: Partial<IncidentDetail> = {}): IncidentDetail {
  return {
    incident_id: "inc-1",
    title: "T",
    severity: "HIGH",
    status: "OPEN",
    confidence: 0.9,
    risk_score: 60,
    risk_band: "HIGH",
    reason: "r",
    risk_explanation: "e",
    detection_ids: ["det-a"],
    evidence_event_ids: ["evt-1"],
    incident_metadata: {},
    mitre_techniques: [],
    risk_breakdown: null,
    ueba_evidence: null,
    created_at: "2026-09-05T09:00:00+00:00",
    updated_at: "2026-09-05T09:00:00+00:00",
    first_seen: "2026-09-05T08:00:00+00:00",
    last_seen: "2026-09-05T09:00:00+00:00",
    ...partial,
  };
}

describe("aggregateRules", () => {
  it("groups firings by rule with traceable spans", () => {
    const catalog = aggregateRules([detA, detB]);
    expect(catalog.total_detections).toBe(2);
    expect(catalog.rules).toHaveLength(1);
    expect(catalog.rules[0]).toMatchObject({
      rule_id: "AUTH-001",
      firings: 2,
      max_confidence: 0.8,
      first_seen: "2026-09-05T08:00:00+00:00",
      last_seen: "2026-09-05T09:05:00+00:00",
    });
    expect(catalog.rules[0].severities).toEqual(["HIGH", "MEDIUM"]);
  });

  it("returns empty catalog for no detections", () => {
    expect(aggregateRules([])).toMatchObject({ rules: [], total_detections: 0 });
  });
});

describe("aggregateTechniques", () => {
  it("uses only techniques present in incident mappings", () => {
    const coverage = aggregateTechniques([
      incident({
        incident_id: "inc-1",
        detection_ids: ["det-a", "det-b"],
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
      }),
      incident({ incident_id: "inc-2", detection_ids: ["det-c"], mitre_techniques: [] }),
    ]);
    expect(coverage.techniques).toHaveLength(1);
    expect(coverage.techniques[0]).toMatchObject({
      technique_id: "T1110",
      source_rule_ids: ["AUTH-001"],
      incident_ids: ["inc-1"],
    });
    expect(coverage.techniques[0].detection_ids).toEqual(["det-a", "det-b"]);
    expect(coverage.incidents_scanned).toBe(2);
  });

  it("never fabricates techniques", () => {
    expect(aggregateTechniques([incident()]).techniques).toEqual([]);
  });
});

describe("aggregateAnomalies", () => {
  it("renders stored scores verbatim with incident context", () => {
    const result = aggregateAnomalies([
      incident({
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
      }),
    ]);
    expect(result.anomalies).toHaveLength(1);
    expect(result.anomalies[0]).toMatchObject({
      entity_key: "user:alice",
      anomaly_score: 0.9,
      anomaly_flag: true,
      incident_id: "inc-1",
    });
  });

  it("skips incidents without UEBA evidence and fabricates nothing", () => {
    expect(aggregateAnomalies([incident()]).anomalies).toEqual([]);
  });
});

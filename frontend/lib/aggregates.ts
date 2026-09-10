/** Pure aggregation over persisted API records for the SOC intelligence views.
 *
 *  Every output identifier (detection, incident, technique, entity) comes
 *  verbatim from the input records. Nothing is invented: rules that never
 *  fired, techniques with no mappings, and entities with no observations
 *  simply do not appear.
 */

import type { DetectionSummary, IncidentDetail } from "@/lib/types";

export const MAX_DETECTION_PAGES = 20;
export const DETECTION_PAGE_SIZE = 100;
export const MAX_INCIDENT_DETAILS = 200;

export interface RuleRow {
  rule_id: string;
  rule_name: string;
  severities: string[];
  firings: number;
  max_confidence: number;
  first_seen: string;
  last_seen: string;
  reasons: string[];
}

export interface RuleCatalog {
  rules: RuleRow[];
  total_detections: number;
  truncated: boolean;
}

export function aggregateRules(detections: DetectionSummary[]): RuleCatalog {
  const byRule = new Map<string, DetectionSummary[]>();
  for (const det of detections) {
    const group = byRule.get(det.rule_id) ?? [];
    group.push(det);
    byRule.set(det.rule_id, group);
  }
  const rules: RuleRow[] = [...byRule.entries()].map(([rule_id, group]) => {
    const severities = [...new Set(group.map((d) => d.severity))].sort();
    const reasons = [...new Set(group.map((d) => d.reason))].slice(0, 3);
    const times = group.flatMap((d) => [d.first_seen, d.last_seen]).sort();
    return {
      rule_id,
      rule_name: group[0].rule_name,
      severities,
      firings: group.length,
      max_confidence: Math.max(...group.map((d) => d.confidence)),
      first_seen: times[0],
      last_seen: times[times.length - 1],
      reasons,
    };
  });
  rules.sort((a, b) => b.firings - a.firings || a.rule_id.localeCompare(b.rule_id));
  return { rules, total_detections: detections.length, truncated: false };
}

export interface TechniqueRow {
  technique_id: string;
  technique_name: string;
  tactic: string;
  source_rule_ids: string[];
  incident_ids: string[];
  detection_ids: string[];
  severities: string[];
  max_risk_score: number;
}

export interface MitreCoverage {
  techniques: TechniqueRow[];
  incidents_scanned: number;
  truncated: boolean;
}

export function aggregateTechniques(incidents: IncidentDetail[]): MitreCoverage {
  const byTechnique = new Map<string, {
    name: string; tactic: string; rules: Set<string>;
    incidents: Set<string>; detections: Set<string>;
    severities: Set<string>; max_risk: number;
  }>();
  for (const inc of incidents) {
    for (const mapping of inc.mitre_techniques) {
      let row = byTechnique.get(mapping.technique_id);
      if (!row) {
        row = {
          name: mapping.technique_name, tactic: mapping.tactic,
          rules: new Set(), incidents: new Set(), detections: new Set(),
          severities: new Set(), max_risk: 0,
        };
        byTechnique.set(mapping.technique_id, row);
      }
      row.rules.add(mapping.source_rule_id);
      row.incidents.add(inc.incident_id);
      for (const det of inc.detection_ids) row.detections.add(det);
      row.severities.add(inc.severity);
      row.max_risk = Math.max(row.max_risk, inc.risk_score);
    }
  }
  const techniques: TechniqueRow[] = [...byTechnique.entries()].map(([technique_id, row]) => ({
    technique_id,
    technique_name: row.name,
    tactic: row.tactic,
    source_rule_ids: [...row.rules].sort(),
    incident_ids: [...row.incidents].sort(),
    detection_ids: [...row.detections].sort(),
    severities: [...row.severities].sort(),
    max_risk_score: row.max_risk,
  }));
  techniques.sort(
    (a, b) => b.incident_ids.length - a.incident_ids.length
      || a.technique_id.localeCompare(b.technique_id),
  );
  return { techniques, incidents_scanned: incidents.length, truncated: false };
}

export interface AnomalyRow {
  entity_key: string;
  anomaly_score: number | null;
  anomaly_flag: boolean | null;
  baseline_status: string;
  incident_id: string;
  incident_severity: string;
  incident_risk_band: string;
  observation_time: string;
  detection_count: number;
}

export interface UebaAnomalies {
  anomalies: AnomalyRow[];
  incidents_scanned: number;
  truncated: boolean;
}

export function aggregateAnomalies(incidents: IncidentDetail[]): UebaAnomalies {
  const anomalies: AnomalyRow[] = [];
  for (const inc of incidents) {
    const evidence = inc.ueba_evidence;
    if (!evidence?.available) continue;
    if (evidence.observations.length === 0) {
      // No per-entity observations stored: attribute the anomaly to the
      // incident itself with an explicit `incident:` namespace so the key
      // can never be mistaken for a real entity.
      anomalies.push({
        entity_key: `incident:${inc.incident_id}`,
        anomaly_score: evidence.anomaly_score,
        anomaly_flag: evidence.anomaly_flag,
        baseline_status: "unknown",
        incident_id: inc.incident_id,
        incident_severity: inc.severity,
        incident_risk_band: inc.risk_band,
        observation_time: inc.last_seen,
        detection_count: inc.detection_ids.length,
      });
      continue;
    }
    for (const obs of evidence.observations) {
      anomalies.push({
        entity_key: obs.entity_key,
        anomaly_score: obs.anomaly_score,
        anomaly_flag: obs.anomaly_flag,
        baseline_status: obs.baseline_status,
        incident_id: inc.incident_id,
        incident_severity: inc.severity,
        incident_risk_band: inc.risk_band,
        observation_time: obs.observation_time,
        detection_count: inc.detection_ids.length,
      });
    }
  }
  anomalies.sort(
    (a, b) => (b.anomaly_score ?? -1) - (a.anomaly_score ?? -1)
      || a.entity_key.localeCompare(b.entity_key),
  );
  return { anomalies, incidents_scanned: incidents.length, truncated: false };
}

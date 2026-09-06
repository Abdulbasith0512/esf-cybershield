/** Backend contract types. Mirror of backend/app/schemas/events.py + api/v1/health.py.
 *  The FastAPI backend is the source of truth; do not add fields here that the
 *  API does not return. */

export interface HealthResponse {
  status: string;
  service: string;
}

export interface SecurityEvent {
  id: string;
  event_id: string;
  timestamp: string;
  event_type: string;
  source: string;
  host: string | null;
  user: string | null;
  source_ip: string | null;
  destination_ip: string | null;
  destination_port: number | null;
  protocol: string | null;
  process_name: string | null;
  parent_process: string | null;
  command_line: string | null;
  file_hash: string | null;
  domain: string | null;
  url: string | null;
  bytes_sent: number | null;
  bytes_received: number | null;
  status: string | null;
  raw_event: Record<string, unknown>;
  created_at: string;
}

export interface EventListResponse {
  items: SecurityEvent[];
  page: number;
  page_size: number;
  total: number;
  pages: number;
}

export interface EventFilters {
  page?: number;
  page_size?: number;
  event_type?: string;
  source?: string;
  host?: string;
  user?: string;
  source_ip?: string;
  destination_ip?: string;
  start_time?: string;
  end_time?: string;
}

export interface MitreMapping {
  technique_id: string;
  technique_name: string;
  tactic: string;
  source_rule_id: string;
  rationale: string;
  confidence: number;
  catalog_version: string;
}

export interface RiskBreakdown {
  severity_points: number;
  diversity_points: number;
  confidence_points: number;
  evidence_points: number;
  sequence_points: number;
  mitre_points: number;
  contextual_points: number;
  total: number;
}

export interface UebaObservationRef {
  entity_key: string;
  observation_time: string;
  anomaly_score: number;
  anomaly_flag: boolean;
  baseline_status: string;
  feature_context: Record<string, number>;
  event_overlap: string[];
}

export interface UebaIncidentEvidence {
  incident_id: string;
  incident_fingerprint: string;
  available: boolean;
  anomaly_score: number | null;
  anomaly_flag: boolean | null;
  model_version: string | null;
  feature_version: string | null;
  feature_window_start: string | null;
  feature_window_end: string | null;
  observations: UebaObservationRef[];
  reason: string;
  metadata: Record<string, unknown>;
}

export interface IncidentSummary {
  incident_id: string;
  title: string;
  severity: string;
  status: string;
  confidence: number;
  risk_score: number;
  risk_band: string;
  ueba_available: boolean;
  ueba_anomaly_score: number | null;
  ueba_anomaly_flag: boolean | null;
  first_seen: string;
  last_seen: string;
}

export interface IncidentDetail extends Omit<IncidentSummary, "ueba_available" | "ueba_anomaly_score" | "ueba_anomaly_flag"> {
  reason: string;
  risk_explanation: string;
  detection_ids: string[];
  evidence_event_ids: string[];
  incident_metadata: Record<string, unknown>;
  mitre_techniques: MitreMapping[];
  risk_breakdown: RiskBreakdown | null;
  ueba_evidence: UebaIncidentEvidence | null;
  created_at: string;
  updated_at: string;
}

export interface IncidentListResponse {
  items: IncidentSummary[];
  page: number;
  page_size: number;
  total: number;
  pages: number;
}

export interface IncidentFilters {
  page?: number;
  page_size?: number;
  severity?: string;
  status?: string;
  risk_band?: string;
  min_risk_score?: number;
  start_time?: string;
  end_time?: string;
}

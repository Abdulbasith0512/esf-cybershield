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
  assignee?: string | null;
  assigned_at?: string | null;
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

export interface DetectionSummary {
  detection_id: string;
  rule_id: string;
  rule_name: string;
  severity: string;
  confidence: number;
  first_seen: string;
  last_seen: string;
  reason: string;
}

export interface DetectionDetail extends DetectionSummary {
  evidence_event_ids: string[];
  detection_metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface DetectionListResponse {
  items: DetectionSummary[];
  page: number;
  page_size: number;
  total: number;
  pages: number;
}

export interface DetectionFilters {
  page?: number;
  page_size?: number;
  rule_id?: string;
  severity?: string;
  min_confidence?: number;
  start_time?: string;
  end_time?: string;
}

export interface InvestigationTimelineEntry {
  detection_id: string;
  rule_id: string;
  rule_name: string;
  severity: string;
  confidence: number;
  first_seen: string;
  last_seen: string;
  evidence_count: number;
  bucket_count: number;
  bucket_available: boolean;
  mitre_technique_ids: string[];
}

export interface InvestigationEntities {
  source_ips: string[];
  destination_ips: string[];
  ports: number[];
  protocols: string[];
  users: string[];
  hosts: string[];
  processes: string[];
}

export interface InvestigationDetection {
  detection_id: string;
  rule_id: string;
  rule_name: string;
  severity: string;
  confidence: number;
  reason: string;
  fingerprint: string;
  first_seen: string;
  last_seen: string;
  evidence_event_ids: string[];
  bucket_event_ids: string[];
  bucket_available: boolean;
  mitre_technique_ids: string[];
}

export interface InvestigationRiskFactor {
  factor: string;
  points: number;
}

export interface InvestigationExplanation {
  summary: string;
  trigger_detections: string[];
  correlation_reason: string;
  risk_factors: InvestigationRiskFactor[];
  mitre_context: { technique_id: string; rule_ids: string[] }[];
  ueba_context: Record<string, unknown>;
  unavailable: string[];
}

export interface Investigation {
  incident: {
    incident_id: string;
    title: string;
    severity: string;
    status: string;
    confidence: number;
    risk_score: number;
    risk_band: string;
    risk_explanation: string;
    first_seen: string;
    last_seen: string;
    created_at: string;
    updated_at: string;
    detection_count: number;
    evidence_count: number;
  };
  explanation: InvestigationExplanation;
  timeline: InvestigationTimelineEntry[];
  entities: InvestigationEntities;
  detections: InvestigationDetection[];
  evidence_sample: Record<string, unknown>[];
  evidence_total: number;
  mitre_techniques: MitreMapping[];
  ueba: Record<string, unknown>;
  risk: {
    score: number;
    band: string;
    explanation: string;
    breakdown: Record<string, unknown>;
    factors: InvestigationRiskFactor[];
  };
  missing_detections: string[];
  case: InvestigationCase | null;
}

export interface InvestigationCaseNote {
  note_id: string;
  author: string | null;
  body: string;
  created_at: string;
}

export interface InvestigationCaseActivity {
  activity_id: string;
  action: string;
  actor: string | null;
  created_at: string;
  metadata: Record<string, unknown>;
}

export interface InvestigationCase {
  status: string;
  assignee: string | null;
  assigned_at: string | null;
  allowed_transitions: string[];
  notes: InvestigationCaseNote[];
  activity: InvestigationCaseActivity[];
}

export interface CaseNote {
  note_id: string;
  incident_id: string;
  author: string | null;
  body: string;
  created_at: string;
}

export interface CaseActivity {
  activity_id: string;
  incident_id: string;
  action: string;
  actor: string | null;
  created_at: string;
  metadata: Record<string, unknown>;
}

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

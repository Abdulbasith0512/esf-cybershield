/** Centralized FastAPI client. All backend calls go through here — components
 *  never call fetch() directly. Backend URL comes from NEXT_PUBLIC_API_BASE_URL.
 */

import type {
  DetectionDetail,
  DetectionFilters,
  DetectionListResponse,
  EventFilters,
  EventListResponse,
  HealthResponse,
  IncidentDetail,
  IncidentFilters,
  IncidentListResponse,
  Investigation,
  SecurityEvent,
} from "@/lib/types";

export class ApiError extends Error {
  status: number;
  detail: unknown;

  constructor(status: number, detail: unknown) {
    super(`API request failed with status ${status}`);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
  }
}

function baseUrl(): string {
  const url = process.env.NEXT_PUBLIC_API_BASE_URL;
  if (!url) {
    throw new Error("NEXT_PUBLIC_API_BASE_URL is not configured");
  }
  return url.replace(/\/$/, "");
}

async function request<T>(path: string, init?: RequestInit, timeoutMs = 10000): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let res: Response;
  try {
    res = await fetch(`${baseUrl()}${path}`, {
      ...init,
      signal: controller.signal,
      headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
    });
  } catch (err) {
    clearTimeout(timer);
    if (err instanceof Error && err.name === "AbortError") {
      throw new ApiError(0, "request timed out");
    }
    throw new ApiError(0, "unable to reach API");
  }
  clearTimeout(timer);
  if (!res.ok) {
    let detail: unknown = null;
    try {
      detail = await res.json();
    } catch {
      detail = await res.text().catch(() => null);
    }
    throw new ApiError(res.status, detail);
  }
  return (await res.json()) as T;
}

export function getHealth(signal?: AbortSignal): Promise<HealthResponse> {
  return request<HealthResponse>("/health", { signal });
}

export function listEvents(filters: EventFilters = {}, signal?: AbortSignal): Promise<EventListResponse> {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(filters)) {
    if (value !== undefined && value !== null && value !== "") {
      params.set(key, String(value));
    }
  }
  const query = params.toString();
  return request<EventListResponse>(`/api/v1/events${query ? `?${query}` : ""}`, { signal });
}

export function getEvent(eventId: string, signal?: AbortSignal): Promise<SecurityEvent> {
  return request<SecurityEvent>(`/api/v1/events/${encodeURIComponent(eventId)}`, { signal });
}

export function listIncidents(filters: IncidentFilters = {}, signal?: AbortSignal): Promise<IncidentListResponse> {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(filters)) {
    if (value !== undefined && value !== null && value !== "") {
      params.set(key, String(value));
    }
  }
  const query = params.toString();
  return request<IncidentListResponse>(`/api/v1/incidents${query ? `?${query}` : ""}`, { signal });
}

export function getIncident(incidentId: string, signal?: AbortSignal): Promise<IncidentDetail> {
  return request<IncidentDetail>(`/api/v1/incidents/${encodeURIComponent(incidentId)}`, { signal });
}

export function getInvestigation(incidentId: string, signal?: AbortSignal): Promise<Investigation> {
  return request<Investigation>(`/api/v1/incidents/${encodeURIComponent(incidentId)}/investigation`, { signal });
}

export function listDetections(filters: DetectionFilters = {}, signal?: AbortSignal): Promise<DetectionListResponse> {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(filters)) {
    if (value !== undefined && value !== null && value !== "") {
      params.set(key, String(value));
    }
  }
  const query = params.toString();
  return request<DetectionListResponse>(`/api/v1/detections${query ? `?${query}` : ""}`, { signal });
}

export function getDetection(detectionId: string, signal?: AbortSignal): Promise<DetectionDetail> {
  return request<DetectionDetail>(`/api/v1/detections/${encodeURIComponent(detectionId)}`, { signal });
}

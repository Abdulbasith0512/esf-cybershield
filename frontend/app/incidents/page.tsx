"use client";

import Link from "next/link";
import { useState } from "react";
import { listIncidents } from "@/lib/api-client";
import type { IncidentSummary } from "@/lib/types";
import { useApi } from "@/lib/use-api";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { SeverityBadge } from "@/components/ui/badge";
import { EmptyState, ErrorState, LoadingState } from "@/components/ui/states";

const PAGE_SIZE = 25;

function formatTime(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString("en-GB", { hour12: false });
}

function UebaCell({ row }: { row: IncidentSummary }) {
  if (!row.ueba_available) return <span className="text-soc-muted">n/a</span>;
  return (
    <span className="inline-flex items-center gap-1.5">
      <span
        aria-hidden="true"
        className={`inline-block h-2 w-2 rounded-full ${row.ueba_anomaly_flag ? "bg-sev-high" : "bg-sev-low"}`}
      />
      {row.ueba_anomaly_flag ? "Flagged" : "Clean"}
      {row.ueba_anomaly_score !== null && (
        <span className="text-soc-muted">({row.ueba_anomaly_score.toFixed(2)})</span>
      )}
    </span>
  );
}

export default function IncidentsPage() {
  const [page, setPage] = useState(1);
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [riskBand, setRiskBand] = useState("");
  const [applied, setApplied] = useState({ severity: "", status: "", riskBand: "" });

  const key = `incidents:p${page}:s${applied.severity}:t${applied.status}:b${applied.riskBand}`;
  const { data, error, loading, refresh } = useApi(key, (signal) =>
    listIncidents(
      {
        page,
        page_size: PAGE_SIZE,
        ...(applied.severity ? { severity: applied.severity } : {}),
        ...(applied.status ? { status: applied.status } : {}),
        ...(applied.riskBand ? { risk_band: applied.riskBand } : {}),
      },
      signal,
    ),
  );

  function applyFilters(e: React.FormEvent) {
    e.preventDefault();
    setPage(1);
    setApplied({ severity, status, riskBand });
  }

  function clear() {
    setSeverity("");
    setStatus("");
    setRiskBand("");
    setPage(1);
    setApplied({ severity: "", status: "", riskBand: "" });
  }

  const selectClass = "rounded border border-soc-border bg-soc-bg px-2 py-1.5 text-sm text-soc-text";

  return (
    <div className="flex flex-col gap-4">
      <header>
        <h1 className="text-xl font-bold text-white">Incidents</h1>
        <p className="text-sm text-soc-muted">Persisted correlated investigation cases, most recent first.</p>
      </header>

      <Card title="Filters">
        <form onSubmit={applyFilters} className="flex flex-wrap items-end gap-3">
          <label className="flex flex-col gap-1 text-xs text-soc-muted">
            Severity
            <select value={severity} onChange={(e) => setSeverity(e.target.value)} className={selectClass}>
              <option value="">All</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </label>
          <label className="flex flex-col gap-1 text-xs text-soc-muted">
            Status
            <select value={status} onChange={(e) => setStatus(e.target.value)} className={selectClass}>
              <option value="">All</option>
              <option value="OPEN">Open</option>
              <option value="INVESTIGATING">Investigating</option>
              <option value="RESOLVED">Resolved</option>
            </select>
          </label>
          <label className="flex flex-col gap-1 text-xs text-soc-muted">
            Risk band
            <select value={riskBand} onChange={(e) => setRiskBand(e.target.value)} className={selectClass}>
              <option value="">All</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </label>
          <Button type="submit">Apply</Button>
          <Button type="button" variant="ghost" onClick={clear}>
            Clear
          </Button>
        </form>
      </Card>

      <Card
        title="Incident queue"
        action={
          <Button variant="ghost" onClick={refresh}>
            Refresh
          </Button>
        }
      >
        {loading && <LoadingState message="Loading incidents..." />}
        {error && !loading && <ErrorState message="Unable to load incidents." onRetry={refresh} />}
        {data && data.items.length === 0 && (
          <EmptyState message="No incidents available." hint="Run the detection pipeline and persist incidents to populate this queue." />
        )}
        {data && data.items.length > 0 && (
          <>
            <div className="overflow-x-auto">
              <table className="w-full min-w-[880px] border-collapse text-left text-sm">
                <thead>
                  <tr className="border-b border-soc-border text-xs uppercase tracking-wide text-soc-muted">
                    <th scope="col" className="px-2 py-2 font-medium">Title</th>
                    <th scope="col" className="px-2 py-2 font-medium">Severity</th>
                    <th scope="col" className="px-2 py-2 font-medium">Status</th>
                    <th scope="col" className="px-2 py-2 font-medium">Risk</th>
                    <th scope="col" className="px-2 py-2 font-medium">Band</th>
                    <th scope="col" className="px-2 py-2 font-medium">UEBA</th>
                    <th scope="col" className="px-2 py-2 font-medium">Last seen</th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((row) => (
                    <tr key={row.incident_id} className="border-b border-soc-border/60 hover:bg-soc-border/30">
                      <td className="max-w-72 truncate px-2 py-2">
                        <Link href={`/incidents/${encodeURIComponent(row.incident_id)}`} className="text-soc-accent underline">
                          {row.title}
                        </Link>
                      </td>
                      <td className="px-2 py-2">
                        <SeverityBadge severity={row.severity} />
                      </td>
                      <td className="px-2 py-2 font-mono text-xs">{row.status}</td>
                      <td className="px-2 py-2 font-mono text-xs">{row.risk_score}</td>
                      <td className="px-2 py-2 font-mono text-xs">{row.risk_band}</td>
                      <td className="px-2 py-2 text-xs">
                        <UebaCell row={row} />
                      </td>
                      <td className="whitespace-nowrap px-2 py-2 font-mono text-xs">{formatTime(row.last_seen)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="mt-3 flex items-center justify-between text-sm text-soc-muted">
              <span>
                Page {data.page} of {data.pages} · {data.total.toLocaleString()} incidents
              </span>
              <span className="flex gap-2">
                <Button variant="ghost" disabled={data.page <= 1} onClick={() => setPage((p) => p - 1)}>
                  Previous
                </Button>
                <Button variant="ghost" disabled={data.page >= data.pages} onClick={() => setPage((p) => p + 1)}>
                  Next
                </Button>
              </span>
            </div>
          </>
        )}
      </Card>
    </div>
  );
}

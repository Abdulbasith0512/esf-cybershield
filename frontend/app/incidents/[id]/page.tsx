"use client";

import Link from "next/link";
import { use } from "react";
import { ApiError, getIncident } from "@/lib/api-client";
import { useApi } from "@/lib/use-api";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { SeverityBadge } from "@/components/ui/badge";
import { EmptyState, ErrorState, LoadingState } from "@/components/ui/states";

function formatTime(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString("en-GB", { hour12: false });
}

function KV({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex flex-col border-b border-soc-border/50 pb-1">
      <dt className="text-xs uppercase tracking-wide text-soc-muted">{label}</dt>
      <dd className="break-all font-mono text-xs text-soc-text">{value}</dd>
    </div>
  );
}

export default function IncidentDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const { data, error, loading, refresh } = useApi(`incident:${id}`, (signal) =>
    getIncident(decodeURIComponent(id), signal),
  );

  return (
    <div className="flex flex-col gap-4">
      <header className="flex flex-wrap items-center justify-between gap-2">
        <Link href="/incidents" className="text-sm text-soc-accent underline">
          ← Back to incident queue
        </Link>
      </header>

      {loading && <LoadingState message="Loading incident..." />}
      {error && !loading && (
        <ErrorState
          message={
            error instanceof ApiError && error.status === 404
              ? "Incident not found."
              : "Unable to load incident."
          }
          onRetry={refresh}
        />
      )}
      {data && (
        <>
          <header className="flex flex-wrap items-center gap-3">
            <h1 className="text-xl font-bold text-white">{data.title}</h1>
            <SeverityBadge severity={data.severity} />
          </header>

          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            {[
              ["Status", data.status],
              ["Risk", `${data.risk_score} / ${data.risk_band}`],
              ["Confidence", data.confidence.toFixed(2)],
              [
                "UEBA",
                !data.ueba_evidence?.available
                  ? "n/a"
                  : `${data.ueba_evidence.anomaly_flag ? "Flagged" : "Clean"} (${data.ueba_evidence.anomaly_score?.toFixed(2) ?? "—"})`,
              ],
            ].map(([label, value]) => (
              <div key={label} className="rounded-md border border-soc-border bg-soc-panel p-3">
                <p className="text-xs uppercase tracking-wide text-soc-muted">{label}</p>
                <p className="mt-1 font-mono text-sm text-white">{value}</p>
              </div>
            ))}
          </div>

          <Card title="Reason">
            <p className="text-sm text-soc-text">{data.reason}</p>
          </Card>

          <Card title={`MITRE ATT&CK hypotheses (${data.mitre_techniques.length})`}>
            {data.mitre_techniques.length === 0 ? (
              <EmptyState message="No MITRE mappings for this incident." />
            ) : (
              <ul className="flex flex-col gap-2">
                {data.mitre_techniques.map((m) => (
                  <li key={`${m.technique_id}:${m.source_rule_id}`} className="rounded border border-soc-border/60 p-2 text-sm">
                    <p className="font-mono text-xs font-semibold text-white">
                      {m.technique_id} — {m.technique_name} <span className="text-soc-muted">[{m.tactic}]</span>
                    </p>
                    <p className="mt-1 text-xs text-soc-muted">
                      via {m.source_rule_id} · confidence {m.confidence} · {m.catalog_version}
                    </p>
                    <p className="mt-1 text-xs text-soc-text">{m.rationale}</p>
                  </li>
                ))}
              </ul>
            )}
          </Card>

          <Card title={`UEBA behavioral evidence`}>
            {!data.ueba_evidence?.available ? (
              <EmptyState message="UEBA evidence unavailable for this incident." />
            ) : (
              <div className="flex flex-col gap-2 text-sm">
                <p className="text-soc-text">{data.ueba_evidence.reason}</p>
                <p className="font-mono text-xs text-soc-muted">
                  model {data.ueba_evidence.model_version} · window {formatTime(data.ueba_evidence.feature_window_start ?? "")} →{" "}
                  {formatTime(data.ueba_evidence.feature_window_end ?? "")}
                </p>
              </div>
            )}
          </Card>

          <Card title={`Detections (${data.detection_ids.length})`}>
            <ul className="flex flex-col gap-1 font-mono text-xs">
              {data.detection_ids.map((d) => (
                <li key={d} className="break-all text-soc-text">{d}</li>
              ))}
            </ul>
          </Card>

          <Card title={`Evidence events (${data.evidence_event_ids.length})`}>
            <p className="mb-2 text-xs text-soc-muted">
              Look up individual events in the <Link href="/events" className="text-soc-accent underline">event browser</Link>.
            </p>
            <ul className="flex flex-col gap-1 font-mono text-xs">
              {data.evidence_event_ids.map((e) => (
                <li key={e} className="break-all text-soc-text">{e}</li>
              ))}
            </ul>
          </Card>

          <Card title="Timeline">
            <dl className="grid grid-cols-1 gap-x-6 gap-y-2 sm:grid-cols-2">
              <KV label="First seen" value={formatTime(data.first_seen)} />
              <KV label="Last seen" value={formatTime(data.last_seen)} />
              <KV label="Incident ID" value={data.incident_id} />
              <KV label="Risk breakdown" value={JSON.stringify(data.risk_breakdown)} />
            </dl>
          </Card>

          <div className="flex justify-end">
            <Button variant="ghost" onClick={refresh}>
              Refresh
            </Button>
          </div>
        </>
      )}
    </div>
  );
}

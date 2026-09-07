"use client";

import Link from "next/link";
import { use, useState } from "react";
import { ApiError, getIncident } from "@/lib/api-client";
import { useApi } from "@/lib/use-api";
import { useIncidentEvidence } from "@/lib/use-incident-evidence";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { SeverityBadge } from "@/components/ui/badge";
import { EmptyState, ErrorState, LoadingState } from "@/components/ui/states";
import { formatTime } from "@/components/dashboard/events-table";
import { InvestigationTimeline } from "@/components/incidents/investigation-timeline";
import { EvidenceSection } from "@/components/incidents/evidence-section";
import { RiskBreakdownView } from "@/components/incidents/risk-breakdown";
import { UebaObservations } from "@/components/incidents/ueba-observations";
import { IncidentContext } from "@/components/incidents/incident-context";
import { AttackStory } from "@/components/incidents/attack-story";
import type { IncidentDetail } from "@/lib/types";

function CopyableId({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <span className="inline-flex items-center gap-2">
      <code className="break-all font-mono text-xs text-soc-muted">{value}</code>
      <button
        type="button"
        onClick={() => {
          void navigator.clipboard?.writeText(value).then(
            () => setCopied(true),
            () => setCopied(false),
          );
          setTimeout(() => setCopied(false), 1500);
        }}
        aria-label="Copy incident ID"
        className="rounded border border-soc-border px-2 py-0.5 font-mono text-xs text-soc-text hover:bg-soc-border/50"
      >
        {copied ? "Copied" : "Copy"}
      </button>
    </span>
  );
}

function formatDuration(firstSeen: string, lastSeen: string): string {
  const ms = new Date(lastSeen).getTime() - new Date(firstSeen).getTime();
  if (Number.isNaN(ms) || ms < 0) return "—";
  const mins = Math.floor(ms / 60000);
  if (mins < 60) return `${mins}m`;
  return `${Math.floor(mins / 60)}h ${mins % 60}m`;
}

function DetectionsByRule({ incident }: { incident: IncidentDetail }) {
  const byRule = new Map<string, string[]>();
  for (const m of incident.mitre_techniques) {
    const list = byRule.get(m.source_rule_id) ?? [];
    list.push(`${m.technique_id} ${m.technique_name}`);
    byRule.set(m.source_rule_id, list);
  }
  return (
    <div className="flex flex-col gap-3">
      {incident.detection_ids.length === 0 ? (
        <EmptyState message="No detections attached to this incident." />
      ) : (
        <>
          <ul className="flex flex-col gap-1 font-mono text-xs">
            {incident.detection_ids.map((d) => (
              <li key={d} className="break-all text-soc-text">
                {d}
              </li>
            ))}
          </ul>
          {byRule.size > 0 && (
            <div>
              <h3 className="mb-1 text-xs uppercase tracking-wide text-soc-muted">
                Grouped by MITRE source rule
              </h3>
              <ul className="flex flex-col gap-1 text-xs">
                {[...byRule.entries()].map(([rule, techniques]) => (
                  <li key={rule} className="font-mono text-soc-text">
                    {rule} → {techniques.join(", ")}
                  </li>
                ))}
              </ul>
            </div>
          )}
          <p className="text-xs text-soc-muted">
            Full detection objects (rule names, severities, reasons) are not exposed by the
            current API; only persisted detection IDs are shown. Techniques above come from
            the incident&apos;s MITRE mappings.
          </p>
        </>
      )}
    </div>
  );
}

export default function IncidentDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  return <IncidentDetailView id={id} />;
}

export function IncidentDetailView({ id }: { id: string }) {
  const { data, error, loading, refresh } = useApi(`incident:${id}`, (signal) =>
    getIncident(decodeURIComponent(id), signal),
  );
  const evidence = useIncidentEvidence(data ? data.evidence_event_ids : null);

  return (
    <div className="flex flex-col gap-4">
      <header className="flex flex-wrap items-center justify-between gap-2">
        <Link href="/incidents" className="text-sm text-soc-accent underline">
          ← Back to incident queue
        </Link>
      </header>

      {loading && <LoadingState message="Loading incident investigation..." />}
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
          <header className="flex flex-col gap-2">
            <div className="flex flex-wrap items-center gap-3">
              <h1 className="text-xl font-bold text-white">{data.title}</h1>
              <SeverityBadge severity={data.severity} />
            </div>
            <CopyableId value={data.incident_id} />
            <p className="font-mono text-xs text-soc-muted">
              {formatTime(data.first_seen)} → {formatTime(data.last_seen)} · duration{" "}
              {formatDuration(data.first_seen, data.last_seen)} · confidence {data.confidence.toFixed(2)} ·
              status {data.status}
            </p>
          </header>

          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            {[
              ["Deterministic risk", `${data.risk_score} / ${data.risk_band}`],
              [
                "UEBA",
                !data.ueba_evidence?.available
                  ? "n/a"
                  : `${data.ueba_evidence.anomaly_flag ? "Flagged" : "Clean"} (${data.ueba_evidence.anomaly_score?.toFixed(2) ?? "—"})`,
              ],
              ["Detections", String(data.detection_ids.length)],
              ["Evidence events", String(data.evidence_event_ids.length)],
            ].map(([label, value]) => (
              <div key={label} className="rounded-md border border-soc-border bg-soc-panel p-3">
                <p className="text-xs uppercase tracking-wide text-soc-muted">{label}</p>
                <p className="mt-1 font-mono text-sm text-white">{value}</p>
              </div>
            ))}
          </div>

          <Card title="Investigation summary">
            <p className="text-sm leading-relaxed text-soc-text">{data.reason}</p>
          </Card>

          <Card title="Attack story">
            {evidence.loading ? (
              <LoadingState message="Loading security telemetry..." />
            ) : (
              <AttackStory incident={data} events={evidence.items} />
            )}
          </Card>

          <Card
            title={`Attack timeline (${evidence.items.length})`}
            action={
              <Button variant="ghost" onClick={refresh}>
                Refresh
              </Button>
            }
          >
            {evidence.loading ? (
              <LoadingState message="Loading security telemetry..." />
            ) : (
              <InvestigationTimeline
                events={evidence.items}
                firstSeen={data.first_seen}
                lastSeen={data.last_seen}
              />
            )}
          </Card>

          <Card title={`Detection evidence (${data.detection_ids.length})`}>
            <DetectionsByRule incident={data} />
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

          <Card title="UEBA behavioral evidence">
            <UebaObservations ueba={data.ueba_evidence} />
          </Card>

          <Card title={`Risk breakdown`}>
            <RiskBreakdownView breakdown={data.risk_breakdown} explanation={data.risk_explanation} />
          </Card>

          <Card title={`Evidence events (${data.evidence_event_ids.length})`}>
            {evidence.loading ? (
              <LoadingState message="Loading security telemetry..." />
            ) : evidence.failed.length > 0 && evidence.items.length === 0 ? (
              <ErrorState message="Unable to load incident evidence." />
            ) : (
              <EvidenceSection items={evidence.items} failed={evidence.failed} />
            )}
          </Card>

          <Card title="Technical context">
            <IncidentContext incident={data} />
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

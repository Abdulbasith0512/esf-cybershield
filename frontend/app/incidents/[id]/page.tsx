"use client";

import Link from "next/link";
import { use, useState } from "react";
import { ApiError, getIncident, getInvestigation } from "@/lib/api-client";
import { useApi } from "@/lib/use-api";
import { useIncidentEvidence } from "@/lib/use-incident-evidence";
import { useIncidentDetections } from "@/lib/use-incident-detections";
import { DetectionCards } from "@/components/incidents/detection-cards";
import { CaseSection } from "@/components/incidents/case-section";
import { EntitySummary } from "@/components/incidents/entity-summary";
import { ExplanationCard } from "@/components/incidents/explanation-card";
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

export default function IncidentDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  return <IncidentDetailView id={id} />;
}

export function IncidentDetailView({ id }: { id: string }) {
  const { data, error, loading, refresh } = useApi(`incident:${id}`, (signal) =>
    getIncident(decodeURIComponent(id), signal),
  );
  const evidence = useIncidentEvidence(data ? data.evidence_event_ids : null);
  const detections = useIncidentDetections(data ? data.detection_ids : null);
  const investigation = useApi(`investigation:${id}`, (signal) =>
    getInvestigation(decodeURIComponent(id), signal),
  );
  const [focusIds, setFocusIds] = useState<string[] | null>(null);
  const bucketTotal = investigation.data
    ? investigation.data.detections.reduce((n, d) => n + d.bucket_event_ids.length, 0)
    : null;

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
              ["Bucket events", bucketTotal === null ? "—" : String(bucketTotal)],
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

          <Card title="Why this incident exists">
            {investigation.loading ? (
              <LoadingState message="Loading investigation..." />
            ) : investigation.error || !investigation.data ? (
              <ErrorState message="Unable to load investigation." onRetry={investigation.refresh} />
            ) : (
              <ExplanationCard explanation={investigation.data.explanation} />
            )}
          </Card>

          <Card title="Entities">
            {investigation.loading ? (
              <LoadingState message="Loading investigation..." />
            ) : investigation.error || !investigation.data ? (
              <ErrorState message="Unable to load investigation." onRetry={investigation.refresh} />
            ) : (
              <EntitySummary entities={investigation.data.entities} />
            )}
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
            {detections.loading ? (
              <LoadingState message="Loading detection details..." />
            ) : (
              <DetectionCards
                items={detections.items}
                failed={detections.failed}
                onFocusEvidence={setFocusIds}
              />
            )}
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
              <>
                {focusIds !== null && (
                  <p className="mb-2 text-xs text-soc-accent" role="status">
                    Highlighting {focusIds.length} event{focusIds.length === 1 ? "" : "s"} from the
                    selected detection.{" "}
                    <button type="button" onClick={() => setFocusIds(null)} className="underline">
                      Clear
                    </button>
                  </p>
                )}
                <EvidenceSection items={evidence.items} failed={evidence.failed} highlightIds={focusIds} />
              </>
            )}
          </Card>

          <Card title="Technical context">
            <IncidentContext incident={data} />
          </Card>

          <Card title="Case management">
            {investigation.loading ? (
              <LoadingState message="Loading case state..." />
            ) : investigation.error || !investigation.data ? (
              <ErrorState message="Unable to load case state." onRetry={investigation.refresh} />
            ) : (
              <CaseSection
                incidentId={data.incident_id}
                caseState={investigation.data.case}
                onChanged={investigation.refresh}
              />
            )}
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

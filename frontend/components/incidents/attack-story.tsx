import type { IncidentDetail, SecurityEvent } from "@/lib/types";
import { formatTime } from "@/components/dashboard/events-table";
import { EmptyState } from "@/components/ui/states";

interface Stage {
  label: string;
  detail: string;
  timestamp: string | null;
}

/** Attack story derived strictly from present detections + evidence.
 *  Stages with no supporting data are omitted, never invented. */
export function AttackStory({
  incident,
  events,
}: {
  incident: IncidentDetail;
  events: SecurityEvent[];
}) {
  const byId = new Map(events.map((e) => [e.event_id, e]));
  const inEvidence = (ids: string[]) => ids.map((id) => byId.get(id)).filter((e) => e !== undefined);

  const ruleSet = new Set(
    Array.isArray(incident.incident_metadata?.rule_ids)
      ? (incident.incident_metadata.rule_ids as unknown[]).filter((r): r is string => typeof r === "string")
      : [],
  );

  const mitreByRule = new Map<string, string[]>();
  for (const m of incident.mitre_techniques) {
    const list = mitreByRule.get(m.source_rule_id) ?? [];
    list.push(m.technique_id);
    mitreByRule.set(m.source_rule_id, list);
  }

  const stages: Stage[] = [];
  const pushStage = (ruleIds: string[], label: string, eventIds: string[]) => {
    if (!ruleIds.some((r) => ruleSet.has(r))) return;
    const evts = inEvidence(eventIds).sort(
      (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime(),
    );
    if (evts.length === 0) return;
    const first = evts[0];
    stages.push({
      label,
      detail: `${evts.length} event${evts.length === 1 ? "" : "s"} · ${[...new Set(evts.map((e) => e.event_type))].join(", ")} · techniques ${(ruleIds.flatMap((r) => mitreByRule.get(r) ?? [])).join(", ") || "—"}`,
      timestamp: first.timestamp,
    });
  };

  pushStage(["AUTH-001", "AUTH-003", "AUTH-002"], "Authentication anomalies", incident.evidence_event_ids.filter((id) => {
    const e = byId.get(id);
    return e?.event_type === "authentication";
  }));
  pushStage(["PROC-001", "PROC-002"], "Suspicious process execution", incident.evidence_event_ids.filter((id) => {
    const e = byId.get(id);
    return e?.event_type === "process_creation";
  }));
  pushStage(["NET-001", "NET-002"], "Suspicious network activity", incident.evidence_event_ids.filter((id) => {
    const e = byId.get(id);
    return e?.event_type === "network_connection" || e?.event_type === "dns_query";
  }));
  pushStage(["DATA-001"], "Large outbound transfer", incident.evidence_event_ids.filter((id) => {
    const e = byId.get(id);
    return e?.event_type === "data_transfer";
  }));

  if (stages.length === 0) {
    return <EmptyState message="No staged attack story can be derived from the present evidence." />;
  }

  return (
    <ol className="relative ml-2 border-l border-soc-border">
      {stages.map((s, i) => (
        <li key={`${s.label}:${i}`} className="relative pb-4 pl-6">
          <span
            aria-hidden="true"
            className="absolute -left-[13px] top-0.5 flex h-6 w-6 items-center justify-center rounded-full border border-soc-accent/60 bg-soc-bg font-mono text-[11px] text-soc-accent"
          >
            {i + 1}
          </span>
          <p className="text-sm font-medium text-soc-text">{s.label}</p>
          <p className="mt-0.5 text-xs text-soc-muted">{s.detail}</p>
          {s.timestamp && <p className="mt-0.5 font-mono text-xs text-soc-muted">{formatTime(s.timestamp)}</p>}
        </li>
      ))}
    </ol>
  );
}

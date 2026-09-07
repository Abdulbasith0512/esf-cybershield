import type { IncidentDetail } from "@/lib/types";

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];
}

function asString(value: unknown): string | null {
  return typeof value === "string" && value !== "" ? value : null;
}

/** Compact entity summary from persisted incident_metadata. Only values
 *  actually present are shown; nothing is inferred or labeled as attacker. */
export function IncidentContext({ incident }: { incident: IncidentDetail }) {
  const meta = incident.incident_metadata ?? {};
  const user = asString(meta.user);
  const host = asString(meta.host);
  const ruleIds = asStringArray(meta.rule_ids);
  const sequenceHits: string[] = Array.isArray(meta.sequence_hits)
    ? meta.sequence_hits
        .filter((p): p is unknown[] => Array.isArray(p))
        .map((p) => p.filter((x): x is string => typeof x === "string").join(" + "))
        .filter((s) => s !== "")
    : [];

  const rows: Array<[string, string[]]> = [
    ["User", user ? [user] : []],
    ["Host", host ? [host] : []],
    ["Rule IDs", ruleIds],
    ["Recognized sequences", sequenceHits],
  ].filter(([, values]) => values.length > 0) as Array<[string, string[]]>;

  if (rows.length === 0) {
    return <p className="text-sm text-soc-muted">No technical context recorded for this incident.</p>;
  }
  return (
    <dl className="grid grid-cols-1 gap-x-6 gap-y-2 sm:grid-cols-2">
      {rows.map(([label, values]) => (
        <div key={label} className="flex flex-col border-b border-soc-border/50 pb-1">
          <dt className="text-xs uppercase tracking-wide text-soc-muted">{label}</dt>
          {values.map((v) => (
            <dd key={v} className="break-all font-mono text-xs text-soc-text">
              {v}
            </dd>
          ))}
        </div>
      ))}
    </dl>
  );
}

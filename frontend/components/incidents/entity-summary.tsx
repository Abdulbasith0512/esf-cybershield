"use client";

import type { InvestigationEntities } from "@/lib/types";

const GROUPS: { key: keyof InvestigationEntities; label: string; mono?: boolean }[] = [
  { key: "source_ips", label: "Source IPs", mono: true },
  { key: "destination_ips", label: "Destination IPs", mono: true },
  { key: "ports", label: "Ports", mono: true },
  { key: "protocols", label: "Protocols" },
  { key: "users", label: "Users" },
  { key: "hosts", label: "Hosts", mono: true },
  { key: "processes", label: "Processes", mono: true },
];

/** Entity summary over the sampled evidence. Empty categories render as
 *  "Not available" — never inferred. */
export function EntitySummary({ entities }: { entities: InvestigationEntities }) {
  return (
    <dl className="grid grid-cols-1 gap-2 sm:grid-cols-2">
      {GROUPS.map(({ key, label, mono }) => {
        const values = entities[key];
        return (
          <div key={key} className="rounded border border-soc-border/60 p-2">
            <dt className="text-xs uppercase tracking-wide text-soc-muted">{label}</dt>
            <dd className={`mt-1 text-sm ${mono ? "font-mono" : ""} text-soc-text`}>
              {values.length === 0 ? "Not available" : values.map(String).join(", ")}
            </dd>
          </div>
        );
      })}
    </dl>
  );
}

"use client";

import { useState } from "react";
import type { SecurityEvent } from "@/lib/types";
import { EventsTable } from "@/components/dashboard/events-table";
import { EventDetail } from "@/components/dashboard/event-detail";
import { Card } from "@/components/ui/card";
import { EmptyState } from "@/components/ui/states";
import type { EvidenceFailure } from "@/lib/use-incident-evidence";

/** Hydrated evidence events: selectable table + detail, plus row-level
 *  retrieval failures. Never fabricates missing rows. */
export function EvidenceSection({
  items,
  failed,
  highlightIds = null,
}: {
  items: SecurityEvent[];
  failed: EvidenceFailure[];
  highlightIds?: string[] | null;
}) {
  const [selected, setSelected] = useState<SecurityEvent | null>(null);
  const highlight = highlightIds === null ? null : new Set(highlightIds);
  const visible = highlight === null ? items : items.filter((e) => highlight.has(e.event_id));

  return (
    <div className="flex flex-col gap-4">
      {failed.length > 0 && (
        <div role="alert" className="rounded border border-sev-high/50 bg-sev-high/10 p-3">
          <p className="text-sm font-medium text-sev-high">
            {failed.length} referenced event{failed.length === 1 ? "" : "s"} could not be retrieved.
          </p>
          <ul className="mt-1 font-mono text-xs text-soc-muted">
            {failed.map((f) => (
              <li key={f.eventId}>
                {f.eventId} ({f.status === 404 ? "not found" : "unreachable"})
              </li>
            ))}
          </ul>
        </div>
      )}
      {items.length === 0 ? (
        <EmptyState message="No evidence events associated with this incident." />
      ) : visible.length === 0 ? (
        <EmptyState message="No evidence events match the selected detection filter." />
      ) : (
        <>
          <EventsTable events={visible} onSelect={setSelected} selectedId={selected?.id ?? null} />
          {selected && (
            <Card title={`Event detail — ${selected.event_id}`}>
              <EventDetail event={selected} />
            </Card>
          )}
        </>
      )}
    </div>
  );
}

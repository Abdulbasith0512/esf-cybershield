"use client";

/** Hydrate incident evidence events via bounded parallel GETs.
 *  One missing event degrades to a row-level failure, never a page error.
 */

import { useEffect, useState } from "react";
import { ApiError, getEvent } from "@/lib/api-client";
import type { SecurityEvent } from "@/lib/types";

export interface EvidenceFailure {
  eventId: string;
  status: number | null;
}

export interface EvidenceState {
  items: SecurityEvent[];
  failed: EvidenceFailure[];
  loading: boolean;
}

export function sortEvidenceEvents(events: SecurityEvent[]): SecurityEvent[] {
  return [...events].sort((a, b) => {
    const ta = new Date(a.timestamp).getTime();
    const tb = new Date(b.timestamp).getTime();
    if (Number.isNaN(ta) && Number.isNaN(tb)) return a.event_id.localeCompare(b.event_id);
    if (Number.isNaN(ta)) return 1;
    if (Number.isNaN(tb)) return -1;
    if (ta !== tb) return ta - tb;
    return a.event_id.localeCompare(b.event_id);
  });
}

interface Snapshot extends EvidenceState {
  key: string;
}

export function useIncidentEvidence(eventIds: string[] | null): EvidenceState {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const ids = eventIds ?? [];
  const key = ids.join(",");

  useEffect(() => {
    const controller = new AbortController();
    let cancelled = false;

    async function run(unique: string[]) {
      const settled = await Promise.allSettled(
        unique.map((id) =>
          getEvent(id, controller.signal).then(
            (event) => ({ ok: true as const, event }),
            (err: unknown) => ({
              ok: false as const,
              eventId: id,
              status: err instanceof ApiError ? err.status : null,
            }),
          ),
        ),
      );
      if (cancelled) return;
      const items: SecurityEvent[] = [];
      const failed: EvidenceFailure[] = [];
      for (const r of settled) {
        if (r.status === "rejected") {
          failed.push({ eventId: "unknown", status: null });
          continue;
        }
        if (r.value.ok) items.push(r.value.event);
        else failed.push({ eventId: r.value.eventId, status: r.value.status });
      }
      setSnapshot({ key, items: sortEvidenceEvents(items), failed, loading: false });
    }

    run([...new Set(ids)]);
    return () => {
      cancelled = true;
      controller.abort();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- key is the stable serialization of ids
  }, [key]);

  if (snapshot !== null && snapshot.key === key) return snapshot;
  return { items: [], failed: [], loading: true };
}

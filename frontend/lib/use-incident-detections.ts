"use client";

/** Hydrate incident detections via bounded parallel GETs.
 *  One missing detection degrades to a row-level failure, never a page error.
 */

import { useEffect, useState } from "react";
import { ApiError, getDetection } from "@/lib/api-client";
import type { DetectionDetail } from "@/lib/types";

export interface DetectionFailure {
  detectionId: string;
  status: number | null;
}

export interface DetectionsState {
  items: DetectionDetail[];
  failed: DetectionFailure[];
  loading: boolean;
}

interface Snapshot extends DetectionsState {
  key: string;
}

export function useIncidentDetections(detectionIds: string[] | null): DetectionsState {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const ids = detectionIds ?? [];
  const key = ids.join(",");

  useEffect(() => {
    const controller = new AbortController();
    let cancelled = false;

    async function run(unique: string[]) {
      const settled = await Promise.allSettled(
        unique.map((id) =>
          getDetection(id, controller.signal).then(
            (detection) => ({ ok: true as const, detection }),
            (err: unknown) => ({
              ok: false as const,
              detectionId: id,
              status: err instanceof ApiError ? err.status : null,
            }),
          ),
        ),
      );
      if (cancelled) return;
      const items: DetectionDetail[] = [];
      const failed: DetectionFailure[] = [];
      for (const r of settled) {
        if (r.status === "rejected") {
          failed.push({ detectionId: "unknown", status: null });
          continue;
        }
        if (r.value.ok) items.push(r.value.detection);
        else failed.push({ detectionId: r.value.detectionId, status: r.value.status });
      }
      items.sort((a, b) => a.rule_id.localeCompare(b.rule_id) || a.detection_id.localeCompare(b.detection_id));
      setSnapshot({ key, items, failed, loading: false });
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

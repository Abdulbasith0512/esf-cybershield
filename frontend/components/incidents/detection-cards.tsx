"use client";

import { useState } from "react";
import type { DetectionDetail } from "@/lib/types";
import { SeverityBadge } from "@/components/ui/badge";
import { EmptyState } from "@/components/ui/states";
import { formatTime } from "@/components/dashboard/events-table";
import type { DetectionFailure } from "@/lib/use-incident-detections";

function DetectionCard({
  detection,
  onFocusEvidence,
}: {
  detection: DetectionDetail;
  onFocusEvidence?: (eventIds: string[]) => void;
}) {
  const [open, setOpen] = useState(false);
  return (
    <li className="rounded border border-soc-border/60 p-3">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="flex w-full flex-wrap items-center gap-2 text-left"
      >
        <span className="font-mono text-xs font-bold text-white">{detection.rule_id}</span>
        <SeverityBadge severity={detection.severity} />
        <span className="text-sm text-soc-text">{detection.rule_name}</span>
        <span className="ml-auto font-mono text-xs text-soc-muted">
          conf {detection.confidence.toFixed(2)} · {detection.evidence_event_ids.length} events
        </span>
      </button>
      {open && (
        <div className="mt-2 flex flex-col gap-2 border-t border-soc-border/50 pt-2">
          <p className="text-sm text-soc-text">{detection.reason}</p>
          <p className="font-mono text-xs text-soc-muted">
            {formatTime(detection.first_seen)} → {formatTime(detection.last_seen)}
          </p>
          <div>
            <p className="mb-1 text-xs uppercase tracking-wide text-soc-muted">Evidence events</p>
            <ul className="flex flex-col gap-1 font-mono text-xs">
              {detection.evidence_event_ids.map((e) => (
                <li key={e} className="break-all text-soc-text">
                  {e}
                </li>
              ))}
            </ul>
            {onFocusEvidence && detection.evidence_event_ids.length > 0 && (
              <button
                type="button"
                onClick={() => onFocusEvidence(detection.evidence_event_ids)}
                className="mt-2 rounded border border-soc-border px-2 py-1 text-xs text-soc-accent underline"
              >
                View evidence below
              </button>
            )}
          </div>
        </div>
      )}
    </li>
  );
}

/** Persisted detection cards. Never invents rule names or reasons. */
export function DetectionCards({
  items,
  failed,
  onFocusEvidence,
}: {
  items: DetectionDetail[];
  failed: DetectionFailure[];
  onFocusEvidence?: (eventIds: string[]) => void;
}) {
  return (
    <div className="flex flex-col gap-3">
      {failed.length > 0 && (
        <div role="alert" className="rounded border border-sev-high/50 bg-sev-high/10 p-3">
          <p className="text-sm font-medium text-sev-high">Detection details unavailable.</p>
          <ul className="mt-1 font-mono text-xs text-soc-muted">
            {failed.map((f) => (
              <li key={f.detectionId}>
                {f.detectionId} ({f.status === 404 ? "not found" : "unreachable"})
              </li>
            ))}
          </ul>
        </div>
      )}
      {items.length === 0 && failed.length === 0 ? (
        <EmptyState message="No detections attached to this incident." />
      ) : (
        <ul className="flex flex-col gap-2">
          {items.map((d) => (
            <DetectionCard key={d.detection_id} detection={d} onFocusEvidence={onFocusEvidence} />
          ))}
        </ul>
      )}
    </div>
  );
}

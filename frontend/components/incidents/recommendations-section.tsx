"use client";

import type { Recommendation } from "@/lib/types";
import { SeverityBadge } from "@/components/ui/badge";

/** Advisory response recommendations. Read-only guidance generated from
 *  stored incident data — nothing here executes containment or remediation. */
export function RecommendationsList({ recommendations }: { recommendations: Recommendation[] }) {
  if (recommendations.length === 0) {
    return <p className="text-sm text-soc-muted">No recommendations for this incident.</p>;
  }
  return (
    <div className="flex flex-col gap-3">
      <p className="text-xs text-soc-muted">
        Advisory only — nothing here has been executed. Validate each item before acting.
      </p>
      <ul className="flex flex-col gap-2">
        {recommendations.map((rec) => (
          <li
            key={rec.id}
            className="rounded border border-soc-border/60 p-2 text-sm"
          >
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={rec.priority} />
              <span className="font-mono text-xs uppercase tracking-wide text-soc-muted">
                {rec.category}
              </span>
              <p className="font-semibold text-white">{rec.title}</p>
            </div>
            <p className="mt-1 text-xs text-soc-text">{rec.reason}</p>
            {rec.actions.length > 0 && (
              <ul className="mt-1 flex list-disc flex-col gap-0.5 pl-5">
                {rec.actions.map((action) => (
                  <li key={action} className="text-xs text-soc-text">
                    {action}
                  </li>
                ))}
              </ul>
            )}
            <p className="mt-1 font-mono text-xs text-soc-muted">
              {rec.evidence_refs.detection_count} detection
              {rec.evidence_refs.detection_count === 1 ? "" : "s"}
              {rec.evidence_refs.detection_ids.length > 0 &&
                `: ${rec.evidence_refs.detection_ids.join(", ")}`}
              {rec.evidence_refs.technique_id &&
                ` · technique ${rec.evidence_refs.technique_id}`}
            </p>
          </li>
        ))}
      </ul>
    </div>
  );
}

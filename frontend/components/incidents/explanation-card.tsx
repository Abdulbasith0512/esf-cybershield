"use client";

import type { InvestigationExplanation } from "@/lib/types";

/** Deterministic "why does this incident exist" summary. Renders only
 *  stored facts; anything unknown arrives pre-marked as unavailable. */
export function ExplanationCard({ explanation }: { explanation: InvestigationExplanation }) {
  return (
    <div className="flex flex-col gap-2">
      <p className="text-sm leading-relaxed text-soc-text">{explanation.summary}</p>
      <p className="text-sm text-soc-text">
        <span className="font-semibold text-white">Correlation: </span>
        {explanation.correlation_reason}
      </p>
      {explanation.risk_factors.length > 0 && (
        <ul className="flex flex-col gap-1">
          {explanation.risk_factors.map((f) => (
            <li key={f.factor} className="font-mono text-xs text-soc-muted">
              +{f.points} — {f.factor}
            </li>
          ))}
        </ul>
      )}
      {explanation.trigger_detections.length > 0 && (
        <p className="font-mono text-xs text-soc-muted">
          trigger detections: {explanation.trigger_detections.join(", ")}
        </p>
      )}
      {explanation.unavailable.length > 0 && (
        <p className="text-xs text-soc-muted">
          Unavailable: {explanation.unavailable.join("; ")}.
        </p>
      )}
    </div>
  );
}

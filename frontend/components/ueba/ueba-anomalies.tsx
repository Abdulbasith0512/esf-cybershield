"use client";

import Link from "next/link";
import { SeverityBadge } from "@/components/ui/badge";
import type { UebaAnomalies } from "@/lib/aggregates";

/** Anomaly rows built from persisted incident UEBA evidence. Scores are
 *  rendered verbatim from the backend; nothing is computed here. */
export function UebaAnomaliesView({ anomalies }: { anomalies: UebaAnomalies }) {
  return (
    <div className="flex flex-col gap-3">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
        {[
          ["Anomalies recorded", String(anomalies.anomalies.length)],
          ["Incidents scanned", String(anomalies.incidents_scanned)],
          ["Coverage", anomalies.truncated ? "truncated" : "complete"],
        ].map(([label, value]) => (
          <div key={label} className="rounded-md border border-soc-border bg-soc-bg p-3">
            <p className="text-xs uppercase tracking-wide text-soc-muted">{label}</p>
            <p className="mt-1 font-mono text-sm text-white">{value}</p>
          </div>
        ))}
      </div>
      <ul className="flex flex-col gap-2">
        {anomalies.anomalies.map((anomaly) => (
          <li
            key={`${anomaly.entity_key}:${anomaly.incident_id}`}
            className="rounded border border-soc-border/60 p-3"
          >
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={anomaly.incident_severity} />
              <span className="break-all font-mono text-xs font-bold text-white">
                {anomaly.entity_key}
              </span>
              <span className="ml-auto font-mono text-xs text-soc-muted">
                score {anomaly.anomaly_score === null ? "—" : anomaly.anomaly_score.toFixed(2)} ·{" "}
                {anomaly.anomaly_flag === null
                  ? "flag unknown"
                  : anomaly.anomaly_flag
                    ? "flagged"
                    : "not flagged"}
              </span>
            </div>
            <p className="mt-1 font-mono text-xs text-soc-muted">
              baseline {anomaly.baseline_status} · band {anomaly.incident_risk_band} ·{" "}
              {anomaly.detection_count} detection{anomaly.detection_count === 1 ? "" : "s"} ·{" "}
              <Link
                href={`/incidents/${encodeURIComponent(anomaly.incident_id)}`}
                className="text-soc-accent underline"
              >
                incident {anomaly.incident_id.slice(0, 8)}
              </Link>
            </p>
          </li>
        ))}
      </ul>
    </div>
  );
}

"use client";

import Link from "next/link";
import { MetricCard } from "@/components/ui/metric-card";
import { SeverityBadge } from "@/components/ui/badge";
import type { MitreCoverage } from "@/lib/aggregates";

/** Technique coverage aggregated from persisted incident MITRE mappings. */
export function MitreCoverageView({ coverage }: { coverage: MitreCoverage }) {
  return (
    <div className="flex flex-col gap-3">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
        <MetricCard label="Techniques observed" value={String(coverage.techniques.length)} />
        <MetricCard label="Incidents scanned" value={String(coverage.incidents_scanned)} />
        <MetricCard label="Coverage" value={coverage.truncated ? "truncated" : "complete"} />
      </div>
      <ul className="flex flex-col gap-2">
        {coverage.techniques.map((technique) => (
          <li key={technique.technique_id} className="rounded border border-soc-border/60 p-3">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-xs font-bold text-white">{technique.technique_id}</span>
              {technique.severities.map((severity) => (
                <SeverityBadge key={severity} severity={severity} />
              ))}
              <span className="text-sm text-soc-text">{technique.technique_name}</span>
              <span className="font-mono text-xs text-soc-muted">[{technique.tactic}]</span>
              <span className="ml-auto font-mono text-xs text-soc-muted">
                risk ≤ {technique.max_risk_score}
              </span>
            </div>
            <p className="mt-1 font-mono text-xs text-soc-muted">
              via {technique.source_rule_ids.join(", ")}
            </p>
            <p className="mt-1 text-xs text-soc-text">
              Detections: {technique.detection_ids.length} · Incidents:{" "}
              {technique.incident_ids.map((id, index) => (
                <span key={id}>
                  {index > 0 && ", "}
                  <Link href={`/incidents/${encodeURIComponent(id)}`} className="text-soc-accent underline">
                    {id.slice(0, 8)}
                  </Link>
                </span>
              ))}
            </p>
          </li>
        ))}
      </ul>
    </div>
  );
}

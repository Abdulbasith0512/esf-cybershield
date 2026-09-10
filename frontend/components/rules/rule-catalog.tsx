"use client";

import { SeverityBadge } from "@/components/ui/badge";
import { MetricCard } from "@/components/ui/metric-card";
import { formatTime } from "@/components/dashboard/events-table";
import type { RuleCatalog } from "@/lib/aggregates";

/** Read-only rule catalog derived from persisted detection firings. */
export function RuleCatalogView({ catalog }: { catalog: RuleCatalog }) {
  return (
    <div className="flex flex-col gap-3">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
        <MetricCard label="Rules fired" value={String(catalog.rules.length)} />
        <MetricCard label="Total detections" value={String(catalog.total_detections)} />
        <MetricCard label="Coverage" value={catalog.truncated ? "truncated" : "complete"} />
      </div>
      <ul className="flex flex-col gap-2">
        {catalog.rules.map((rule) => (
          <li key={rule.rule_id} className="rounded border border-soc-border/60 p-3">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-xs font-bold text-white">{rule.rule_id}</span>
              {rule.severities.map((severity) => (
                <SeverityBadge key={severity} severity={severity} />
              ))}
              <span className="text-sm text-soc-text">{rule.rule_name}</span>
              <span className="ml-auto font-mono text-xs text-soc-muted">
                {rule.firings} firing{rule.firings === 1 ? "" : "s"} · conf{" "}
                {rule.max_confidence.toFixed(2)}
              </span>
            </div>
            <p className="mt-1 font-mono text-xs text-soc-muted">
              {formatTime(rule.first_seen)} → {formatTime(rule.last_seen)}
            </p>
            {rule.reasons.length > 0 && (
              <ul className="mt-1 flex list-disc flex-col gap-0.5 pl-5">
                {rule.reasons.map((reason) => (
                  <li key={reason} className="text-xs text-soc-text">
                    {reason}
                  </li>
                ))}
              </ul>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}

"use client";

import { listIncidents } from "@/lib/api-client";
import { Card } from "@/components/ui/card";
import { EmptyState, ErrorState, LoadingState } from "@/components/ui/states";
import { SeverityBadge } from "@/components/ui/badge";
import { useApi } from "@/lib/use-api";

const LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;

async function fetchDistribution(signal: AbortSignal) {
  const entries = await Promise.all(
    LEVELS.map(async (severity) => {
      const res = await listIncidents({ severity, page: 1, page_size: 1 }, signal);
      return { severity, total: res.total };
    }),
  );
  return entries;
}

/** Incident counts per severity, each total straight from the list API. */
export function SeverityDistribution() {
  const { data, error, loading, refresh } = useApi("incident-severity-mix", fetchDistribution);

  return (
    <Card title="Incidents by severity">
      {loading && <LoadingState message="Loading severity mix..." />}
      {error && !loading && (
        <ErrorState message="Unable to load severity mix." onRetry={refresh} />
      )}
      {data && data.every((entry) => entry.total === 0) && (
        <EmptyState message="No incidents available." />
      )}
      {data && data.some((entry) => entry.total > 0) && (
        <ul className="flex flex-col gap-2.5">
          {(() => {
            const max = Math.max(...data.map((entry) => entry.total));
            return data.map((entry) => (
              <li key={entry.severity} className="flex items-center gap-3 text-sm">
                <span className="w-28 shrink-0">
                  <SeverityBadge severity={entry.severity} />
                </span>
                <span className="h-2 min-w-0 flex-1 overflow-hidden rounded bg-soc-border/50">
                  <span
                    className="block h-full rounded bg-soc-accent"
                    style={{ width: `${max === 0 ? 0 : Math.max(2, (entry.total / max) * 100)}%` }}
                  />
                </span>
                <span className="w-14 shrink-0 text-right font-mono text-xs text-soc-muted">
                  {entry.total.toLocaleString()}
                </span>
              </li>
            ));
          })()}
        </ul>
      )}
      {data && (
        <p className="mt-2 text-xs text-soc-muted">Persisted incidents, all statuses.</p>
      )}
    </Card>
  );
}

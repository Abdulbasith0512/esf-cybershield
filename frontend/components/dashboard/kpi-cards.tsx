"use client";

import { useMemo } from "react";
import { listEvents } from "@/lib/api-client";
import { Card } from "@/components/ui/card";
import { EmptyState, ErrorState, LoadingState } from "@/components/ui/states";
import { Button } from "@/components/ui/button";
import { MetricCard } from "@/components/ui/metric-card";
import { useApi } from "@/lib/use-api";

export function KpiCards() {
  const { data, error, loading, refresh } = useApi("overview-kpis", (signal) =>
    listEvents({ page: 1, page_size: 100 }, signal),
  );

  const byType = useMemo(() => {
    const counts = new Map<string, number>();
    for (const e of data?.items ?? []) counts.set(e.event_type, (counts.get(e.event_type) ?? 0) + 1);
    return [...counts.entries()].sort((a, b) => b[1] - a[1]);
  }, [data]);

  if (loading) {
    return (
      <div aria-label="Key metrics">
        <LoadingState message="Loading security telemetry..." />
      </div>
    );
  }
  if (error || !data) {
    return (
      <div aria-label="Key metrics">
        <ErrorState message="Unable to load security telemetry." onRetry={refresh} />
      </div>
    );
  }
  if (data.total === 0) {
    return (
      <div aria-label="Key metrics">
        <EmptyState message="No security events available." />
      </div>
    );
  }

  const failed = (data?.items ?? []).filter((e) => e.status === "failed").length;

  return (
    <div aria-label="Key metrics">
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard label="Total events" value={data.total.toLocaleString()} hint="from event store" />
        <MetricCard label="Failed authentications" value={String(failed)} hint="in latest 100 events" />
        <MetricCard
          label="Top event type"
          value={byType[0]?.[0] ?? "—"}
          hint={byType[0] ? `${byType[0][1]} of latest 100` : undefined}
        />
        <MetricCard label="Sources" value={String(new Set(data.items.map((e) => e.source)).size)} hint="in latest 100 events" />
      </div>
      <Card title="Events by type (latest 100)">
        {byType.length === 0 ? (
          <EmptyState message="No security events available." />
        ) : (
          <ul className="flex flex-col gap-2">
            {byType.map(([type, count]) => (
              <li key={type} className="flex items-center gap-3 text-sm">
                <span className="w-40 truncate font-mono text-xs text-soc-text">{type}</span>
                <span className="h-2 flex-1 overflow-hidden rounded bg-soc-border/50">
                  <span
                    className="block h-full rounded bg-soc-accent"
                    style={{ width: `${Math.max(2, (count / data.items.length) * 100)}%` }}
                  />
                </span>
                <span className="w-10 text-right font-mono text-xs text-soc-muted">{count}</span>
              </li>
            ))}
          </ul>
        )}
      </Card>
      <div className="mt-3 flex justify-end">
        <Button variant="ghost" onClick={refresh}>
          Refresh metrics
        </Button>
      </div>
    </div>
  );
}

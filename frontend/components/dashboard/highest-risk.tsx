"use client";

import Link from "next/link";
import { listIncidents } from "@/lib/api-client";
import { Card } from "@/components/ui/card";
import { EmptyState, ErrorState, LoadingState } from "@/components/ui/states";
import { SeverityBadge } from "@/components/ui/badge";
import { useApi } from "@/lib/use-api";

const RECENT_WINDOW = 25;
const TOP_COUNT = 5;

async function fetchHighestRisk(signal: AbortSignal) {
  const res = await listIncidents({ page: 1, page_size: RECENT_WINDOW }, signal);
  return [...res.items]
    .sort((a, b) => b.risk_score - a.risk_score || b.last_seen.localeCompare(a.last_seen))
    .slice(0, TOP_COUNT);
}

/** Top risk scores among the most recent incidents (API returns recency
 *  order; the top-5 cut is labeled as such, never a global claim). */
export function HighestRisk() {
  const { data, error, loading, refresh } = useApi("highest-risk", fetchHighestRisk);

  return (
    <Card title={`Highest risk · recent ${RECENT_WINDOW}`}>
      {loading && <LoadingState message="Loading incident risk..." />}
      {error && !loading && (
        <ErrorState message="Unable to load incident risk." onRetry={refresh} />
      )}
      {data && data.length === 0 && <EmptyState message="No incidents available." />}
      {data && data.length > 0 && (
        <ul className="flex flex-col gap-2">
          {data.map((row) => (
            <li
              key={row.incident_id}
              className="flex items-center gap-3 rounded border border-soc-border/60 px-3 py-2"
            >
              <SeverityBadge severity={row.severity} />
              <Link
                href={`/incidents/${encodeURIComponent(row.incident_id)}`}
                className="min-w-0 flex-1 truncate text-sm text-soc-accent underline"
              >
                {row.title}
              </Link>
              <span className="shrink-0 font-mono text-xs text-soc-muted">
                risk {row.risk_score} · {row.risk_band}
              </span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

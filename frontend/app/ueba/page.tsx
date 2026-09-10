"use client";

import { Card } from "@/components/ui/card";
import { EmptyState, ErrorState, LoadingState } from "@/components/ui/states";
import { UebaAnomaliesView } from "@/components/ueba/ueba-anomalies";
import { MAX_INCIDENT_DETAILS } from "@/lib/aggregates";
import { aggregateAnomalies } from "@/lib/aggregates";
import { getIncident, listIncidents } from "@/lib/api-client";
import { useApi } from "@/lib/use-api";
import type { IncidentDetail } from "@/lib/types";

async function fetchAnomalies(signal: AbortSignal) {
  const first = await listIncidents({ page: 1, page_size: 100 }, signal);
  const ids = [...first.items.map((item) => item.incident_id)];
  for (let page = 2; page <= first.pages; page += 1) {
    const next = await listIncidents({ page, page_size: 100 }, signal);
    ids.push(...next.items.map((item) => item.incident_id));
  }
  const selected = ids.slice(0, MAX_INCIDENT_DETAILS);
  const details: IncidentDetail[] = await Promise.all(
    selected.map((id) => getIncident(id, signal)),
  );
  const anomalies = aggregateAnomalies(details);
  anomalies.truncated = ids.length > MAX_INCIDENT_DETAILS;
  return anomalies;
}

export default function UebaPage() {
  const { data, error, loading, refresh } = useApi("ueba-anomalies", fetchAnomalies);

  return (
    <div className="flex flex-col gap-4">
      <header>
        <h1 className="text-xl font-bold text-white">UEBA</h1>
        <p className="text-sm text-soc-muted">Behavioral baselines and anomaly scores.</p>
      </header>
      <Card title="Behavioral anomalies">
        {loading ? (
          <LoadingState message="Loading incident UEBA evidence..." />
        ) : error || !data ? (
          <ErrorState message="Unable to load UEBA anomalies." onRetry={refresh} />
        ) : data.anomalies.length === 0 ? (
          <EmptyState
            message="No UEBA anomalies recorded yet."
            hint="Anomalies appear here once incidents carry stored UEBA evidence."
          />
        ) : (
          <UebaAnomaliesView anomalies={data} />
        )}
      </Card>
    </div>
  );
}

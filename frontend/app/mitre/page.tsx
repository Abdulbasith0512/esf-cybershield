"use client";

import { Card } from "@/components/ui/card";
import { EmptyState, ErrorState, LoadingState } from "@/components/ui/states";
import { MitreCoverageView } from "@/components/mitre/mitre-coverage";
import { MAX_INCIDENT_DETAILS } from "@/lib/aggregates";
import { aggregateTechniques } from "@/lib/aggregates";
import { getIncident, listIncidents } from "@/lib/api-client";
import { useApi } from "@/lib/use-api";
import type { IncidentDetail } from "@/lib/types";

async function fetchCoverage(signal: AbortSignal) {
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
  const coverage = aggregateTechniques(details);
  coverage.truncated = ids.length > MAX_INCIDENT_DETAILS;
  return coverage;
}

export default function MitrePage() {
  const { data, error, loading, refresh } = useApi("mitre-coverage", fetchCoverage);

  return (
    <div className="flex flex-col gap-4">
      <header>
        <h1 className="text-xl font-bold text-white">MITRE ATT&amp;CK</h1>
        <p className="text-sm text-soc-muted">Technique coverage mapped from detections.</p>
      </header>
      <Card title="Technique coverage">
        {loading ? (
          <LoadingState message="Loading incident MITRE mappings..." />
        ) : error || !data ? (
          <ErrorState message="Unable to load MITRE coverage." onRetry={refresh} />
        ) : data.techniques.length === 0 ? (
          <EmptyState
            message="No MITRE techniques mapped yet."
            hint="Techniques appear here once incidents carry stored ATT&CK mappings."
          />
        ) : (
          <MitreCoverageView coverage={data} />
        )}
      </Card>
    </div>
  );
}

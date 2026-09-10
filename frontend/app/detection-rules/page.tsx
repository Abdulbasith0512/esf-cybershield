"use client";

import { Card } from "@/components/ui/card";
import { EmptyState, ErrorState, LoadingState } from "@/components/ui/states";
import { RuleCatalogView } from "@/components/rules/rule-catalog";
import { aggregateRules, DETECTION_PAGE_SIZE, MAX_DETECTION_PAGES } from "@/lib/aggregates";
import { listDetections } from "@/lib/api-client";
import { useApi } from "@/lib/use-api";
import type { DetectionSummary } from "@/lib/types";

async function fetchCatalog(signal: AbortSignal) {
  const first = await listDetections({ page: 1, page_size: DETECTION_PAGE_SIZE }, signal);
  const items: DetectionSummary[] = [...first.items];
  const pages = Math.min(first.pages, MAX_DETECTION_PAGES);
  for (let page = 2; page <= pages; page += 1) {
    const next = await listDetections({ page, page_size: DETECTION_PAGE_SIZE }, signal);
    items.push(...next.items);
  }
  const catalog = aggregateRules(items);
  catalog.truncated = first.pages > MAX_DETECTION_PAGES;
  return catalog;
}

export default function DetectionRulesPage() {
  const { data, error, loading, refresh } = useApi("rule-catalog", fetchCatalog);

  return (
    <div className="flex flex-col gap-4">
      <header>
        <h1 className="text-xl font-bold text-white">Detection Rules</h1>
        <p className="text-sm text-soc-muted">Deterministic rule catalog and firing history.</p>
      </header>
      <Card title="Rule catalog">
        {loading ? (
          <LoadingState message="Loading persisted detections..." />
        ) : error || !data ? (
          <ErrorState message="Unable to load detection rules." onRetry={refresh} />
        ) : data.rules.length === 0 ? (
          <EmptyState
            message="No persisted detections yet."
            hint="Rules appear here once detectors fire and detections are persisted."
          />
        ) : (
          <RuleCatalogView catalog={data} />
        )}
      </Card>
    </div>
  );
}

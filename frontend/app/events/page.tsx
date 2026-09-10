"use client";

import { useState } from "react";
import { getEvent, listEvents } from "@/lib/api-client";
import type { SecurityEvent } from "@/lib/types";
import { useApi } from "@/lib/use-api";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/ui/page-header";
import { EmptyState, ErrorState, LoadingState } from "@/components/ui/states";
import { EventsTable } from "@/components/dashboard/events-table";
import { EventDetail } from "@/components/dashboard/event-detail";

const PAGE_SIZE = 25;

export default function EventsPage() {
  const [page, setPage] = useState(1);
  const [eventType, setEventType] = useState("");
  const [user, setUser] = useState("");
  const [applied, setApplied] = useState({ eventType: "", user: "" });
  const [selected, setSelected] = useState<SecurityEvent | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);

  const key = `events:p${page}:t${applied.eventType}:u${applied.user}`;
  const { data, error, loading, refresh } = useApi(key, (signal) =>
    listEvents(
      {
        page,
        page_size: PAGE_SIZE,
        ...(applied.eventType ? { event_type: applied.eventType } : {}),
        ...(applied.user ? { user: applied.user } : {}),
      },
      signal,
    ),
  );

  async function select(row: SecurityEvent) {
    setDetailError(null);
    try {
      setSelected(await getEvent(row.event_id));
    } catch {
      setDetailError("Unable to load event detail.");
    }
  }

  function applyFilters(e: React.FormEvent) {
    e.preventDefault();
    setPage(1);
    setSelected(null);
    setApplied({ eventType, user });
  }

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="Security Events"
        subtitle="Server-paginated event store. Select a row for detail."
      />

      <Card title="Filters">
        <form onSubmit={applyFilters} className="flex flex-wrap items-end gap-3">
          <label className="flex flex-col gap-1 text-xs text-soc-muted">
            Event type
            <input
              value={eventType}
              onChange={(e) => setEventType(e.target.value)}
              placeholder="authentication"
              className="rounded border border-soc-border bg-soc-bg px-2 py-1.5 text-sm text-soc-text"
            />
          </label>
          <label className="flex flex-col gap-1 text-xs text-soc-muted">
            User
            <input
              value={user}
              onChange={(e) => setUser(e.target.value)}
              placeholder="john.doe"
              className="rounded border border-soc-border bg-soc-bg px-2 py-1.5 text-sm text-soc-text"
            />
          </label>
          <Button type="submit">Apply</Button>
          <Button
            type="button"
            variant="ghost"
            onClick={() => {
              setEventType("");
              setUser("");
              setPage(1);
              setSelected(null);
              setApplied({ eventType: "", user: "" });
            }}
          >
            Clear
          </Button>
        </form>
      </Card>

      <Card
        title="Events"
        action={
          <Button variant="ghost" onClick={refresh}>
            Refresh
          </Button>
        }
      >
        {loading && <LoadingState message="Loading security telemetry..." />}
        {error && !loading && <ErrorState message="Unable to load security telemetry." onRetry={refresh} />}
        {data && data.items.length === 0 && <EmptyState message="No security events available." />}
        {data && data.items.length > 0 && (
          <>
            <EventsTable events={data.items} onSelect={select} selectedId={selected?.id ?? null} />
            <div className="mt-3 flex items-center justify-between text-sm text-soc-muted">
              <span>
                Page {data.page} of {data.pages} · {data.total.toLocaleString()} events
              </span>
              <span className="flex gap-2">
                <Button variant="ghost" disabled={data.page <= 1} onClick={() => setPage((p) => p - 1)}>
                  Previous
                </Button>
                <Button variant="ghost" disabled={data.page >= data.pages} onClick={() => setPage((p) => p + 1)}>
                  Next
                </Button>
              </span>
            </div>
          </>
        )}
      </Card>

      {detailError && <ErrorState message={detailError} />}
      {selected && (
        <Card title={`Event detail — ${selected.event_id}`}>
          <EventDetail event={selected} />
        </Card>
      )}
    </div>
  );
}

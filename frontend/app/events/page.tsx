"use client";

import { useState } from "react";
import { getEvent, listEvents } from "@/lib/api-client";
import type { SecurityEvent } from "@/lib/types";
import { useApi } from "@/lib/use-api";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { EmptyState, ErrorState, LoadingState } from "@/components/ui/states";
import { EventsTable, formatCell, formatTime } from "@/components/dashboard/events-table";

const PAGE_SIZE = 25;

function EventDetail({ event }: { event: SecurityEvent }) {
  const rows: Array<[string, string]> = [
    ["Event ID", event.event_id],
    ["Record ID", event.id],
    ["Timestamp", formatTime(event.timestamp)],
    ["Type", formatCell(event.event_type)],
    ["Source", formatCell(event.source)],
    ["User", formatCell(event.user)],
    ["Host", formatCell(event.host)],
    ["Source IP", formatCell(event.source_ip)],
    ["Destination IP", formatCell(event.destination_ip)],
    ["Destination port", formatCell(event.destination_port)],
    ["Protocol", formatCell(event.protocol)],
    ["Process", formatCell(event.process_name)],
    ["Parent process", formatCell(event.parent_process)],
    ["Command line", formatCell(event.command_line)],
    ["File hash", formatCell(event.file_hash)],
    ["Domain", formatCell(event.domain)],
    ["URL", formatCell(event.url)],
    ["Bytes sent", formatCell(event.bytes_sent)],
    ["Bytes received", formatCell(event.bytes_received)],
    ["Status", formatCell(event.status)],
  ];
  return (
    <div className="flex flex-col gap-4">
      <dl className="grid grid-cols-1 gap-x-6 gap-y-2 sm:grid-cols-2">
        {rows.map(([label, value]) => (
          <div key={label} className="flex flex-col border-b border-soc-border/50 pb-1">
            <dt className="text-xs uppercase tracking-wide text-soc-muted">{label}</dt>
            <dd className="break-all font-mono text-xs text-soc-text">{value}</dd>
          </div>
        ))}
      </dl>
      <div>
        <h3 className="mb-1 text-xs uppercase tracking-wide text-soc-muted">Raw event</h3>
        <pre className="max-h-64 overflow-auto rounded bg-soc-bg p-3 font-mono text-xs text-soc-text">
          {JSON.stringify(event.raw_event, null, 2)}
        </pre>
      </div>
    </div>
  );
}

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
      <header>
        <h1 className="text-xl font-bold text-white">Security Events</h1>
        <p className="text-sm text-soc-muted">Server-paginated event store. Select a row for detail.</p>
      </header>

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

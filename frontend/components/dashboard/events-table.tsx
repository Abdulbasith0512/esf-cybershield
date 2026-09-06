"use client";

import Link from "next/link";
import { listEvents } from "@/lib/api-client";
import type { SecurityEvent } from "@/lib/types";
import { Card } from "@/components/ui/card";
import { EmptyState, ErrorState, LoadingState } from "@/components/ui/states";
import { Button } from "@/components/ui/button";
import { useApi } from "@/lib/use-api";

export function formatCell(value: string | number | null | undefined): string {
  if (value === null || value === undefined || value === "") return "—";
  return String(value);
}

export function formatTime(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString("en-GB", { hour12: false });
}

export function EventsTable({
  events,
  onSelect,
  selectedId,
}: {
  events: SecurityEvent[];
  onSelect?: (e: SecurityEvent) => void;
  selectedId?: string | null;
}) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[760px] border-collapse text-left text-sm">
        <thead>
          <tr className="border-b border-soc-border text-xs uppercase tracking-wide text-soc-muted">
            <th scope="col" className="px-2 py-2 font-medium">Timestamp</th>
            <th scope="col" className="px-2 py-2 font-medium">Type</th>
            <th scope="col" className="px-2 py-2 font-medium">Source</th>
            <th scope="col" className="px-2 py-2 font-medium">User</th>
            <th scope="col" className="px-2 py-2 font-medium">Host</th>
            <th scope="col" className="px-2 py-2 font-medium">Source IP</th>
            <th scope="col" className="px-2 py-2 font-medium">Dest IP</th>
            <th scope="col" className="px-2 py-2 font-medium">Status</th>
          </tr>
        </thead>
        <tbody>
          {events.map((e) => (
            <tr
              key={e.id}
              onClick={onSelect ? () => onSelect(e) : undefined}
              aria-selected={selectedId === e.id}
              className={`border-b border-soc-border/60 font-mono text-xs ${
                onSelect ? "cursor-pointer hover:bg-soc-border/30" : ""
              } ${selectedId === e.id ? "bg-soc-border/40" : ""}`}
            >
              <td className="whitespace-nowrap px-2 py-2">{formatTime(e.timestamp)}</td>
              <td className="px-2 py-2">{formatCell(e.event_type)}</td>
              <td className="px-2 py-2">{formatCell(e.source)}</td>
              <td className="px-2 py-2">{formatCell(e.user)}</td>
              <td className="px-2 py-2">{formatCell(e.host)}</td>
              <td className="px-2 py-2">{formatCell(e.source_ip)}</td>
              <td className="px-2 py-2">{formatCell(e.destination_ip)}</td>
              <td className="px-2 py-2">{formatCell(e.status)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function RecentEvents({ limit = 10 }: { limit?: number }) {
  const { data, error, loading, refresh } = useApi(`recent-events:${limit}`, (signal) =>
    listEvents({ page: 1, page_size: limit }, signal),
  );

  return (
    <Card
      title="Recent security activity"
      action={
        <Button variant="ghost" onClick={refresh}>
          Refresh
        </Button>
      }
    >
      {loading && <LoadingState message="Loading security telemetry..." />}
      {error && !loading && (
        <ErrorState message="Unable to load security telemetry." onRetry={refresh} />
      )}
      {data && data.items.length === 0 && (
        <EmptyState message="No security events available." hint="Ingest events via the API to populate this view." />
      )}
      {data && data.items.length > 0 && <EventsTable events={data.items} />}
      {data && (
        <p className="mt-2 text-xs text-soc-muted">
          Showing latest {data.items.length} of {data.total} events.{" "}
          <Link href="/events" className="text-soc-accent underline">
            Open full event browser
          </Link>
        </p>
      )}
    </Card>
  );
}

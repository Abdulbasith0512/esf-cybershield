"use client";

import Link from "next/link";
import { listEvents } from "@/lib/api-client";
import type { SecurityEvent } from "@/lib/types";
import { Card } from "@/components/ui/card";
import { EmptyState, ErrorState, LoadingState } from "@/components/ui/states";
import { Button } from "@/components/ui/button";
import { DataTable, TableHead, TableScroll, Td, Th, Tr } from "@/components/ui/table";
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
    <TableScroll label="Security events">
      <DataTable minWidth={760}>
        <TableHead>
          <Th>Timestamp</Th>
          <Th>Type</Th>
          <Th>Source</Th>
          <Th>User</Th>
          <Th>Host</Th>
          <Th>Source IP</Th>
          <Th>Dest IP</Th>
          <Th>Status</Th>
        </TableHead>
        <tbody>
          {events.map((e) => (
            <Tr
              key={e.id}
              onClick={onSelect ? () => onSelect(e) : undefined}
              selected={selectedId === e.id}
            >
              <Td nowrap>{formatTime(e.timestamp)}</Td>
              <Td>{formatCell(e.event_type)}</Td>
              <Td>{formatCell(e.source)}</Td>
              <Td>{formatCell(e.user)}</Td>
              <Td>{formatCell(e.host)}</Td>
              <Td>{formatCell(e.source_ip)}</Td>
              <Td>{formatCell(e.destination_ip)}</Td>
              <Td>{formatCell(e.status)}</Td>
            </Tr>
          ))}
        </tbody>
      </DataTable>
    </TableScroll>
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

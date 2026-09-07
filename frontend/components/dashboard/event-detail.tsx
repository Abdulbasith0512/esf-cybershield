import type { SecurityEvent } from "@/lib/types";
import { formatCell, formatTime } from "@/components/dashboard/events-table";

export function EventDetail({ event }: { event: SecurityEvent }) {
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

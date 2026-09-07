import type { SecurityEvent } from "@/lib/types";
import { formatCell, formatTime } from "@/components/dashboard/events-table";
import { EmptyState } from "@/components/ui/states";

const TYPE_DOT: Array<[RegExp, string]> = [
  [/auth/i, "bg-sev-medium"],
  [/process|file/i, "bg-sev-high"],
  [/network|dns/i, "bg-soc-accent"],
  [/transfer|bytes/i, "bg-sev-critical"],
];

function dotFor(eventType: string): string {
  for (const [re, cls] of TYPE_DOT) {
    if (re.test(eventType)) return cls;
  }
  return "bg-soc-muted";
}

function summarize(event: SecurityEvent): string {
  const parts = [event.event_type, event.status].filter(Boolean).join(" · ");
  const detail =
    event.process_name?.split(/[\\/]/).pop() ??
    event.destination_ip ??
    event.domain ??
    event.source_ip ??
    (event.bytes_sent != null ? `${event.bytes_sent.toLocaleString()} bytes out` : null) ??
    "";
  return detail ? `${parts} — ${detail}` : parts || event.event_id;
}

/** Chronological incident timeline. Expects pre-sorted events (timestamp asc,
 *  event_id tiebreak); re-sorts defensively. Pure presentational. */
export function InvestigationTimeline({
  events,
  firstSeen,
  lastSeen,
  onSelect,
  selectedId,
}: {
  events: SecurityEvent[];
  firstSeen: string;
  lastSeen: string;
  onSelect?: (e: SecurityEvent) => void;
  selectedId?: string | null;
}) {
  if (events.length === 0) {
    return <EmptyState message="No evidence events associated with this incident." />;
  }
  const ordered = [...events].sort((a, b) => {
    const ta = new Date(a.timestamp).getTime();
    const tb = new Date(b.timestamp).getTime();
    if (ta !== tb) return ta - tb;
    return a.event_id.localeCompare(b.event_id);
  });

  return (
    <div>
      <p className="mb-3 font-mono text-xs text-soc-muted">
        Window {formatTime(firstSeen)} → {formatTime(lastSeen)} · {ordered.length} events
      </p>
      <ol className="relative ml-2 border-l border-soc-border">
        {ordered.map((e) => (
          <li key={e.event_id} className="relative pb-4 pl-6">
            <span
              aria-hidden="true"
              className={`absolute -left-[5px] top-1 h-2.5 w-2.5 rounded-full ${dotFor(e.event_type)}`}
            />
            <button
              type="button"
              onClick={onSelect ? () => onSelect(e) : undefined}
              aria-current={selectedId === e.id ? "true" : undefined}
              className={`block w-full rounded p-1 text-left ${onSelect ? "cursor-pointer hover:bg-soc-border/30" : ""} ${
                selectedId === e.id ? "bg-soc-border/40" : ""
              }`}
            >
              <p className="font-mono text-xs text-soc-muted">{formatTime(e.timestamp)}</p>
              <p className="mt-0.5 break-words text-sm text-soc-text">{summarize(e)}</p>
              <p className="mt-0.5 font-mono text-xs text-soc-muted">
                {formatCell(e.user)} · {formatCell(e.host)} · {formatCell(e.source_ip)}
              </p>
            </button>
          </li>
        ))}
      </ol>
    </div>
  );
}

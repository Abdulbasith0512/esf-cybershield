"use client";

import type { EnrichedObservable } from "@/lib/types";

const CLASSIFICATION_STYLES: Record<string, string> = {
  malicious: "border-sev-critical/60 bg-sev-critical/10 text-sev-critical",
  suspicious: "border-sev-medium/60 bg-sev-medium/10 text-sev-medium",
  benign: "border-sev-low/60 bg-sev-low/10 text-sev-low",
  unknown: "border-soc-border bg-soc-bg text-soc-muted",
  unavailable: "border-soc-border bg-soc-bg text-soc-muted",
};

const CLASSIFICATION_GLYPH: Record<string, string> = {
  malicious: "▲",
  suspicious: "◆",
  benign: "○",
  unknown: "?",
  unavailable: "—",
};

function classificationOf(item: EnrichedObservable): string {
  if (!item.available || !item.intelligence) return "unavailable";
  return item.intelligence.classification.toLowerCase();
}

/** Classification indicator: text label + glyph, never color alone. */
export function ClassificationBadge({ classification }: { classification: string }) {
  const key = classification.toLowerCase();
  const style = CLASSIFICATION_STYLES[key] ?? CLASSIFICATION_STYLES.unknown;
  const glyph = CLASSIFICATION_GLYPH[key] ?? "•";
  const label = classification.charAt(0).toUpperCase() + classification.slice(1).toLowerCase();
  return (
    <span
      role="img"
      aria-label={`classification ${label}`}
      className={`inline-flex items-center gap-1.5 rounded border px-2 py-0.5 font-mono text-xs font-semibold ${style}`}
    >
      <span aria-hidden="true">{glyph}</span>
      {label}
    </span>
  );
}

/** Advisory threat-intel enrichment. Renders only the classification the
 *  provider returned; fixture intelligence is always labeled as such. */
export function ThreatIntelList({ items, provider }: { items: EnrichedObservable[]; provider: string }) {
  if (items.length === 0) {
    return <p className="text-sm text-soc-muted">No observables extracted for this incident.</p>;
  }
  const isFixture = provider === "local-test";
  return (
    <div className="flex flex-col gap-3">
      <p className="text-xs text-soc-muted">
        Source: {provider}
        {isFixture && " fixture (test intelligence — not real threat data)"}. Advisory only —
        classifications come from the provider, never from detector severity.
      </p>
      <ul className="flex flex-col gap-2">
        {items.map((item) => {
          const classification = classificationOf(item);
          const intel = item.intelligence;
          return (
            <li
              key={`${item.observable.type}:${item.observable.normalized_value}:${item.observable.source}`}
              className="rounded border border-soc-border/60 p-2 text-sm"
            >
              <div className="flex flex-wrap items-center gap-2">
                <ClassificationBadge classification={classification} />
                <span className="font-mono text-xs uppercase tracking-wide text-soc-muted">
                  {item.observable.type} · {item.observable.source}
                </span>
                <p className="break-all font-mono text-xs font-semibold text-white">
                  {item.observable.value}
                </p>
              </div>
              <p className="mt-1 font-mono text-xs text-soc-muted">
                {item.observable.event_count} event{item.observable.event_count === 1 ? "" : "s"}
                {item.detection_ids.length > 0 &&
                  ` · detections: ${item.detection_ids.join(", ")}`}
                {intel && ` · confidence ${intel.confidence.toFixed(2)}`}
              </p>
              {intel && intel.categories.length > 0 && (
                <p className="mt-1 font-mono text-xs text-soc-muted">
                  tags: {intel.categories.join(", ")}
                </p>
              )}
              {intel?.retrieved_at && (
                <p className="mt-1 font-mono text-xs text-soc-muted">
                  retrieved {intel.retrieved_at}
                </p>
              )}
              {!item.available && (
                <p className="mt-1 text-xs text-soc-muted">
                  Unavailable{item.error ? `: ${item.error}` : "."}
                </p>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}

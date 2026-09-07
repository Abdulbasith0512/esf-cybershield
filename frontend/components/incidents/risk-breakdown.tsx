import type { RiskBreakdown } from "@/lib/types";
import { EmptyState } from "@/components/ui/states";

const TERMS: Array<[keyof Omit<RiskBreakdown, "total">, string]> = [
  ["severity_points", "Severity"],
  ["diversity_points", "Detection diversity"],
  ["confidence_points", "Confidence"],
  ["evidence_points", "Evidence"],
  ["sequence_points", "Sequence"],
  ["mitre_points", "MITRE"],
  ["contextual_points", "Context"],
];

/** Persisted risk breakdown bars + explanation. Display only — never recomputed. */
export function RiskBreakdownView({
  breakdown,
  explanation,
}: {
  breakdown: RiskBreakdown | null;
  explanation: string;
}) {
  if (!breakdown) {
    return <EmptyState message="No risk breakdown available for this incident." />;
  }
  const max = Math.max(1, ...TERMS.map(([k]) => breakdown[k]));
  return (
    <div className="flex flex-col gap-3">
      <ul className="flex flex-col gap-2">
        {TERMS.map(([key, label]) => (
          <li key={key} className="flex items-center gap-3 text-sm">
            <span className="w-44 shrink-0 text-xs text-soc-muted">{label}</span>
            <span className="h-2 flex-1 overflow-hidden rounded bg-soc-border/50">
              <span
                className="block h-full rounded bg-soc-accent"
                style={{ width: `${Math.max(2, (breakdown[key] / max) * 100)}%` }}
              />
            </span>
            <span className="w-10 text-right font-mono text-xs text-soc-text">{breakdown[key]}</span>
          </li>
        ))}
      </ul>
      <p className="font-mono text-xs text-soc-muted">Total: {breakdown.total} / 100</p>
      <p className="text-sm text-soc-text">{explanation}</p>
    </div>
  );
}

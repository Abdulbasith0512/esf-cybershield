/** Single KPI cell: label, primary value, optional supporting context.
 *  Values always come from API data; this component computes nothing. */
export function MetricCard({
  label,
  value,
  hint,
}: {
  label: string;
  value: string;
  hint?: string;
}) {
  return (
    <div className="rounded-md border border-soc-border bg-soc-panel p-3.5">
      <p className="text-xs font-medium uppercase tracking-wider text-soc-muted">{label}</p>
      <p className="mt-1.5 truncate font-mono text-xl font-semibold text-white" aria-live="polite">
        {value}
      </p>
      {hint && <p className="mt-1 truncate text-xs text-soc-muted">{hint}</p>}
    </div>
  );
}

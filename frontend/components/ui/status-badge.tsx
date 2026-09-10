const STATUS_STYLES: Record<string, string> = {
  OPEN: "border-soc-accent/60 bg-soc-accent/10 text-soc-accent",
  INVESTIGATING: "border-sev-medium/60 bg-sev-medium/10 text-sev-medium",
  CONTAINED: "border-sev-high/60 bg-sev-high/10 text-sev-high",
  RESOLVED: "border-sev-low/60 bg-sev-low/10 text-sev-low",
};

const STATUS_GLYPH: Record<string, string> = {
  OPEN: "○",
  INVESTIGATING: "◆",
  CONTAINED: "●",
  RESOLVED: "✓",
};

/** Case-lifecycle indicator: text label + glyph, never color alone. */
export function StatusBadge({ status }: { status: string }) {
  const key = status.toUpperCase();
  const style = STATUS_STYLES[key] ?? "border-soc-border bg-soc-bg text-soc-muted";
  const glyph = STATUS_GLYPH[key] ?? "•";
  return (
    <span
      role="img"
      aria-label={`status ${status}`}
      className={`inline-flex items-center gap-1.5 rounded border px-2 py-0.5 font-mono text-xs font-semibold ${style}`}
    >
      <span aria-hidden="true">{glyph}</span>
      {status.toUpperCase()}
    </span>
  );
}

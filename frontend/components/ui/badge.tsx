const SEVERITY_STYLES: Record<string, string> = {
  CRITICAL: "border-sev-critical/60 bg-sev-critical/10 text-sev-critical",
  HIGH: "border-sev-high/60 bg-sev-high/10 text-sev-high",
  MEDIUM: "border-sev-medium/60 bg-sev-medium/10 text-sev-medium",
  LOW: "border-sev-low/60 bg-sev-low/10 text-sev-low",
};

const SEVERITY_GLYPH: Record<string, string> = {
  CRITICAL: "▲",
  HIGH: "●",
  MEDIUM: "◆",
  LOW: "○",
};

/** Severity indicator: text label + glyph, never color alone. */
export function SeverityBadge({ severity }: { severity: string }) {
  const key = severity.toUpperCase();
  const style = SEVERITY_STYLES[key] ?? "border-soc-border bg-soc-bg text-soc-muted";
  const glyph = SEVERITY_GLYPH[key] ?? "•";
  return (
    <span
      role="img"
      aria-label={`severity ${severity}`}
      className={`inline-flex items-center gap-1.5 rounded border px-2 py-0.5 font-mono text-xs font-semibold ${style}`}
    >
      <span aria-hidden="true">{glyph}</span>
      {severity.toUpperCase()}
    </span>
  );
}

export function StatusDot({ ok, label }: { ok: boolean | null; label: string }) {
  const color = ok === null ? "bg-soc-muted" : ok ? "bg-sev-low" : "bg-sev-critical";
  return (
    <span className="inline-flex items-center gap-2 text-sm">
      <span aria-hidden="true" className={`inline-block h-2.5 w-2.5 rounded-full ${color}`} />
      <span className="text-soc-muted">{label}:</span>
      <span className="font-medium text-soc-text">
        {ok === null ? "Checking…" : ok ? "Operational" : "Unavailable"}
      </span>
    </span>
  );
}

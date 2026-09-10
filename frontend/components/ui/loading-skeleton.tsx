/** Content-shaped loading placeholders. Announced politely; no spinners war. */
export function LoadingSkeleton({ lines = 3 }: { lines?: number }) {
  return (
    <div role="status" aria-live="polite" aria-label="Loading content" className="flex flex-col gap-2 py-1">
      {Array.from({ length: lines }, (_, index) => (
        <span
          key={index}
          aria-hidden="true"
          className="h-3.5 animate-pulse rounded bg-soc-border/50"
          style={{ width: `${88 - index * 12}%` }}
        />
      ))}
    </div>
  );
}

export function TableSkeleton({ rows = 5, columns = 4 }: { rows?: number; columns?: number }) {
  return (
    <div role="status" aria-live="polite" aria-label="Loading table" className="flex flex-col gap-2">
      {Array.from({ length: rows }, (_, row) => (
        <div key={row} className="flex gap-2" aria-hidden="true">
          {Array.from({ length: columns }, (_, col) => (
            <span key={col} className="h-8 flex-1 animate-pulse rounded bg-soc-border/40" />
          ))}
        </div>
      ))}
    </div>
  );
}

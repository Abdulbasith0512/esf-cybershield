export function LoadingState({ message }: { message: string }) {
  return (
    <div role="status" aria-live="polite" className="flex items-center gap-3 py-6 text-soc-muted">
      <span aria-hidden="true" className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-soc-border border-t-soc-accent" />
      <p className="text-sm">{message}</p>
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div role="alert" className="rounded border border-sev-critical/50 bg-sev-critical/10 p-4">
      <p className="text-sm font-medium text-sev-critical">Unable to load security telemetry.</p>
      <p className="mt-1 text-sm text-soc-muted">{message}</p>
      {onRetry && (
        <button onClick={onRetry} className="mt-3 rounded border border-soc-border px-3 py-1.5 text-sm hover:bg-soc-border/50">
          Retry
        </button>
      )}
    </div>
  );
}

export function EmptyState({ message, hint }: { message: string; hint?: string }) {
  return (
    <div className="rounded border border-dashed border-soc-border p-6 text-center">
      <p className="text-sm font-medium text-soc-text">{message}</p>
      {hint && <p className="mt-1 text-sm text-soc-muted">{hint}</p>}
    </div>
  );
}

export function UnavailableState({ feature }: { feature: string }) {
  return (
    <EmptyState
      message={`${feature}: backend endpoint not available`}
      hint="This section requires an API that is not part of the current backend slice."
    />
  );
}

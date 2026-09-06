import type { ReactNode } from "react";

export function Card({ title, action, children }: { title?: string; action?: ReactNode; children: ReactNode }) {
  return (
    <section className="rounded-md border border-soc-border bg-soc-panel p-4" aria-label={title}>
      {(title || action) && (
        <div className="mb-3 flex items-center justify-between gap-2">
          {title ? <h2 className="text-sm font-semibold tracking-wide text-soc-text">{title}</h2> : <span />}
          {action}
        </div>
      )}
      {children}
    </section>
  );
}

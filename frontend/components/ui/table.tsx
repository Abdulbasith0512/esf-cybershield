import type { ReactNode } from "react";

/** Standardized data-table primitives: horizontal scroll on narrow screens,
 *  sticky muted header row, consistent cell rhythm. Content stays in pages. */
export function TableScroll({ children, label }: { children: ReactNode; label: string }) {
  return (
    <div className="overflow-x-auto" role="region" aria-label={label} tabIndex={0}>
      {children}
    </div>
  );
}

export function DataTable({ children, minWidth = 760 }: { children: ReactNode; minWidth?: number }) {
  return (
    <table className="w-full border-collapse text-left text-sm" style={{ minWidth }}>
      {children}
    </table>
  );
}

export function TableHead({ children }: { children: ReactNode }) {
  return (
    <thead>
      <tr className="border-b border-soc-border text-xs uppercase tracking-wide text-soc-muted">
        {children}
      </tr>
    </thead>
  );
}

export function Th({ children }: { children: ReactNode }) {
  return (
    <th scope="col" className="whitespace-nowrap px-2.5 py-2 font-medium">
      {children}
    </th>
  );
}

export function Tr({
  children,
  selected,
  onClick,
}: {
  children: ReactNode;
  selected?: boolean;
  onClick?: () => void;
}) {
  return (
    <tr
      onClick={onClick}
      aria-selected={selected}
      className={`border-b border-soc-border/60 font-mono text-xs transition-colors ${
        onClick ? "cursor-pointer hover:bg-soc-border/30" : ""
      } ${selected ? "bg-soc-border/40" : ""}`}
    >
      {children}
    </tr>
  );
}

export function Td({ children, nowrap }: { children: ReactNode; nowrap?: boolean }) {
  return <td className={`px-2.5 py-2 ${nowrap ? "whitespace-nowrap" : ""}`}>{children}</td>;
}

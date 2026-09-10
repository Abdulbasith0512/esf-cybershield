"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const GROUPS: { heading: string; items: { href: string; label: string }[] }[] = [
  {
    heading: "Operations",
    items: [
      { href: "/", label: "Overview" },
      { href: "/incidents", label: "Incidents" },
      { href: "/events", label: "Events" },
    ],
  },
  {
    heading: "Detection & Analytics",
    items: [
      { href: "/detection-rules", label: "Detection Rules" },
      { href: "/mitre", label: "MITRE ATT&CK" },
      { href: "/ueba", label: "UEBA" },
    ],
  },
];

export function SidebarNav({ onNavigate }: { onNavigate?: () => void }) {
  const pathname = usePathname();
  return (
    <nav aria-label="Primary" className="flex flex-col gap-4">
      {GROUPS.map((group) => (
        <div key={group.heading}>
          <p className="mb-1.5 px-3 text-[11px] font-semibold uppercase tracking-widest text-soc-muted">
            {group.heading}
          </p>
          <ul className="flex flex-col gap-0.5">
            {group.items.map((item) => {
              const active = pathname === item.href;
              return (
                <li key={item.href}>
                  <Link
                    href={item.href}
                    aria-current={active ? "page" : undefined}
                    onClick={onNavigate}
                    className={`relative block rounded-md px-3 py-2 text-sm font-medium transition-colors ${
                      active
                        ? "bg-soc-border/60 text-white"
                        : "text-soc-muted hover:bg-soc-border/40 hover:text-soc-text"
                    }`}
                  >
                    <span
                      aria-hidden="true"
                      className={`absolute left-0 top-1/2 h-5 w-0.5 -translate-y-1/2 rounded-full ${
                        active ? "bg-soc-accent" : "bg-transparent"
                      }`}
                    />
                    {item.label}
                  </Link>
                </li>
              );
            })}
          </ul>
        </div>
      ))}
    </nav>
  );
}

export function Sidebar({ open, onClose }: { open: boolean; onClose: () => void }) {
  return (
    <>
      {open && (
        <div className="border-b border-soc-border bg-soc-panel p-4 lg:hidden">
          <SidebarNav onNavigate={onClose} />
        </div>
      )}
      <aside className="hidden w-60 shrink-0 flex-col gap-5 border-r border-soc-border bg-soc-panel p-4 lg:flex">
        <div className="px-1">
          <p className="font-mono text-sm font-bold tracking-tight text-white">ESF CyberShield</p>
          <p className="mt-0.5 text-xs text-soc-muted">SOC Analyst Console</p>
        </div>
        <SidebarNav />
        <p className="mt-auto px-1 text-xs leading-relaxed text-soc-muted">
          Frontend never connects directly to PostgreSQL.
        </p>
      </aside>
    </>
  );
}

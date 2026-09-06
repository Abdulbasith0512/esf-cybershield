"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";

const NAV = [
  { href: "/", label: "Overview" },
  { href: "/incidents", label: "Incidents" },
  { href: "/events", label: "Events" },
  { href: "/detection-rules", label: "Detection Rules" },
  { href: "/mitre", label: "MITRE ATT&CK" },
  { href: "/ueba", label: "UEBA" },
];

export function Sidebar() {
  const pathname = usePathname();
  const [open, setOpen] = useState(false);

  const links = (
    <nav aria-label="Primary" className="flex flex-col gap-1">
      {NAV.map((item) => {
        const active = pathname === item.href;
        return (
          <Link
            key={item.href}
            href={item.href}
            aria-current={active ? "page" : undefined}
            onClick={() => setOpen(false)}
            className={`rounded px-3 py-2 text-sm font-medium ${
              active ? "bg-soc-border/70 text-white" : "text-soc-muted hover:bg-soc-border/40 hover:text-soc-text"
            }`}
          >
            {item.label}
          </Link>
        );
      })}
    </nav>
  );

  return (
    <>
      <div className="flex items-center justify-between border-b border-soc-border bg-soc-panel px-4 py-3 lg:hidden">
        <span className="font-mono text-sm font-bold">ESF CyberShield</span>
        <button
          onClick={() => setOpen((v) => !v)}
          aria-expanded={open}
          aria-label="Toggle navigation"
          className="rounded border border-soc-border px-3 py-1.5 text-sm"
        >
          Menu
        </button>
      </div>
      {open && <div className="border-b border-soc-border bg-soc-panel p-3 lg:hidden">{links}</div>}
      <aside className="hidden w-56 shrink-0 flex-col gap-4 border-r border-soc-border bg-soc-panel p-4 lg:flex">
        <div>
          <p className="font-mono text-sm font-bold text-white">ESF CyberShield</p>
          <p className="mt-0.5 text-xs text-soc-muted">SOC Analyst Console</p>
        </div>
        {links}
        <p className="mt-auto text-xs text-soc-muted">Frontend never connects directly to PostgreSQL.</p>
      </aside>
    </>
  );
}

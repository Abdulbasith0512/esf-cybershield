"use client";

import { usePathname } from "next/navigation";
import { HealthStatus } from "@/components/dashboard/health-status";

const CRUMBS: Record<string, string> = {
  "/": "Overview",
  "/incidents": "Incidents",
  "/events": "Events",
  "/detection-rules": "Detection Rules",
  "/mitre": "MITRE ATT&CK",
  "/ueba": "UEBA",
};

function crumbsFor(pathname: string): string[] {
  if (pathname.startsWith("/incidents/") && pathname.length > "/incidents/".length) {
    return ["Incidents", decodeURIComponent(pathname.slice("/incidents/".length)).slice(0, 8)];
  }
  return [CRUMBS[pathname] ?? "Console"];
}

/** Slim top bar: breadcrumb plus live API health. Always visible, all widths. */
export function TopBar({ onMenu }: { onMenu: () => void }) {
  const pathname = usePathname();
  const crumbs = crumbsFor(pathname);
  return (
    <div className="sticky top-0 z-20 flex items-center gap-3 border-b border-soc-border bg-soc-bg/95 px-4 py-2.5 backdrop-blur lg:px-6">
      <button
        type="button"
        onClick={onMenu}
        aria-label="Toggle navigation"
        className="rounded border border-soc-border px-2.5 py-1 font-mono text-xs text-soc-text hover:bg-soc-border/50 lg:hidden"
      >
        Menu
      </button>
      <span className="font-mono text-sm font-bold text-white lg:hidden">ESF</span>
      <nav aria-label="Breadcrumb" className="flex min-w-0 items-center gap-1.5 text-sm">
        <span className="hidden font-mono text-xs text-soc-muted sm:inline">ESF</span>
        <span aria-hidden="true" className="hidden text-soc-muted sm:inline">/</span>
        {crumbs.map((crumb, index) => (
          <span key={`${crumb}-${index}`} className="flex min-w-0 items-center gap-1.5">
            {index > 0 && (
              <span aria-hidden="true" className="text-soc-muted">
                /
              </span>
            )}
            <span className={index === crumbs.length - 1 ? "truncate font-medium text-soc-text" : "truncate text-soc-muted"}>
              {crumb}
            </span>
          </span>
        ))}
      </nav>
      <div className="ml-auto shrink-0">
        <HealthStatus />
      </div>
    </div>
  );
}

"use client";

import { getHealth } from "@/lib/api-client";
import { StatusDot } from "@/components/ui/badge";
import { useApi } from "@/lib/use-api";

export function HealthStatus() {
  const { data, error, loading, refresh } = useApi("health", (signal) => getHealth(signal));

  if (loading) return <StatusDot ok={null} label="API" />;
  if (error || !data) {
    return (
      <span className="inline-flex items-center gap-3">
        <StatusDot ok={false} label="API" />
        <button onClick={refresh} className="text-xs text-soc-accent underline">
          Retry
        </button>
      </span>
    );
  }
  return <StatusDot ok={data.status === "healthy"} label="API" />;
}

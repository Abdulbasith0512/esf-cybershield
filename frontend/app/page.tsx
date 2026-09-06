import { HealthStatus } from "@/components/dashboard/health-status";
import { KpiCards } from "@/components/dashboard/kpi-cards";
import { RecentEvents } from "@/components/dashboard/events-table";

export default function OverviewPage() {
  return (
    <div className="flex flex-col gap-4">
      <header className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h1 className="text-xl font-bold text-white">Security Overview</h1>
          <p className="text-sm text-soc-muted">Live telemetry from the ESF event store.</p>
        </div>
        <HealthStatus />
      </header>
      <KpiCards />
      <RecentEvents limit={10} />
    </div>
  );
}

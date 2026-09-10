import { HighestRisk } from "@/components/dashboard/highest-risk";
import { KpiCards } from "@/components/dashboard/kpi-cards";
import { RecentEvents } from "@/components/dashboard/events-table";
import { SeverityDistribution } from "@/components/dashboard/severity-distribution";
import { PageHeader } from "@/components/ui/page-header";

export default function OverviewPage() {
  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="Security Overview"
        subtitle="Live telemetry from the ESF event store."
      />
      <KpiCards />
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <SeverityDistribution />
        <HighestRisk />
      </div>
      <RecentEvents limit={10} />
    </div>
  );
}

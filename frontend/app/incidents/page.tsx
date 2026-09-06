import { Card } from "@/components/ui/card";
import { UnavailableState } from "@/components/ui/states";

export default function IncidentsPage() {
  return (
    <div className="flex flex-col gap-4">
      <header>
        <h1 className="text-xl font-bold text-white">Incidents</h1>
        <p className="text-sm text-soc-muted">Correlated investigation cases.</p>
      </header>
      <Card title="Incident queue">
        <UnavailableState feature="Incident queue" />
      </Card>
    </div>
  );
}

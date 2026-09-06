import { Card } from "@/components/ui/card";
import { UnavailableState } from "@/components/ui/states";

export default function UebaPage() {
  return (
    <div className="flex flex-col gap-4">
      <header>
        <h1 className="text-xl font-bold text-white">UEBA</h1>
        <p className="text-sm text-soc-muted">Behavioral baselines and anomaly scores.</p>
      </header>
      <Card title="Behavioral anomalies">
        <UnavailableState feature="UEBA anomaly scores" />
      </Card>
    </div>
  );
}

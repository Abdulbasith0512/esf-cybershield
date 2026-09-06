import { Card } from "@/components/ui/card";
import { UnavailableState } from "@/components/ui/states";

export default function DetectionRulesPage() {
  return (
    <div className="flex flex-col gap-4">
      <header>
        <h1 className="text-xl font-bold text-white">Detection Rules</h1>
        <p className="text-sm text-soc-muted">Deterministic rule catalog and firing history.</p>
      </header>
      <Card title="Rule catalog">
        <UnavailableState feature="Detection rule catalog" />
      </Card>
    </div>
  );
}

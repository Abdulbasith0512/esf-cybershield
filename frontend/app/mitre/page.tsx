import { Card } from "@/components/ui/card";
import { UnavailableState } from "@/components/ui/states";

export default function MitrePage() {
  return (
    <div className="flex flex-col gap-4">
      <header>
        <h1 className="text-xl font-bold text-white">MITRE ATT&amp;CK</h1>
        <p className="text-sm text-soc-muted">Technique coverage mapped from detections.</p>
      </header>
      <Card title="Technique coverage">
        <UnavailableState feature="MITRE ATT&CK coverage" />
      </Card>
    </div>
  );
}

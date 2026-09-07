import type { UebaIncidentEvidence } from "@/lib/types";
import { EmptyState } from "@/components/ui/states";
import { formatTime } from "@/components/dashboard/events-table";

/** UEBA behavioral evidence. Three honest states; deterministic risk untouched. */
export function UebaObservations({ ueba }: { ueba: UebaIncidentEvidence | null }) {
  if (!ueba || !ueba.available) {
    return <EmptyState message="UEBA evidence unavailable for this incident." hint={ueba?.reason} />;
  }
  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <span
          role="img"
          aria-label={ueba.anomaly_flag ? "anomalous behavior" : "normal behavior"}
          className={`inline-flex items-center gap-1.5 rounded border px-2 py-0.5 font-mono text-xs font-semibold ${
            ueba.anomaly_flag
              ? "border-sev-high/60 bg-sev-high/10 text-sev-high"
              : "border-sev-low/60 bg-sev-low/10 text-sev-low"
          }`}
        >
          <span aria-hidden="true">{ueba.anomaly_flag ? "●" : "○"}</span>
          {ueba.anomaly_flag ? "ANOMALOUS" : "NORMAL"}
        </span>
        <span className="font-mono text-xs text-soc-text">
          score {ueba.anomaly_score !== null ? ueba.anomaly_score.toFixed(2) : "—"}
        </span>
        <span className="font-mono text-xs text-soc-muted">model {ueba.model_version ?? "—"}</span>
      </div>
      <p className="text-sm text-soc-text">{ueba.reason}</p>
      {ueba.observations.length === 0 ? (
        <EmptyState message="No behavioral observations overlap this incident." />
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[640px] border-collapse text-left text-sm">
            <thead>
              <tr className="border-b border-soc-border text-xs uppercase tracking-wide text-soc-muted">
                <th scope="col" className="px-2 py-2 font-medium">Window</th>
                <th scope="col" className="px-2 py-2 font-medium">Score</th>
                <th scope="col" className="px-2 py-2 font-medium">Flag</th>
                <th scope="col" className="px-2 py-2 font-medium">Baseline</th>
                <th scope="col" className="px-2 py-2 font-medium">Behavioral context</th>
              </tr>
            </thead>
            <tbody>
              {ueba.observations.map((o) => (
                <tr key={`${o.entity_key}:${o.observation_time}`} className="border-b border-soc-border/60 font-mono text-xs">
                  <td className="whitespace-nowrap px-2 py-2">{formatTime(o.observation_time)}</td>
                  <td className="px-2 py-2">{o.anomaly_score.toFixed(2)}</td>
                  <td className="px-2 py-2">{o.anomaly_flag ? "Yes" : "No"}</td>
                  <td className="px-2 py-2">{o.baseline_status}</td>
                  <td className="px-2 py-2">
                    {Object.entries(o.feature_context).map(([k, v]) => (
                      <span key={k} className="mr-2 inline-block">
                        {k}={typeof v === "number" ? v.toLocaleString() : String(v)}
                      </span>
                    ))}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

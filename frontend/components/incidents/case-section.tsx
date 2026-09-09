"use client";

import { useState } from "react";
import { ApiError, createIncidentNote, updateIncidentCase } from "@/lib/api-client";
import type { InvestigationCase } from "@/lib/types";
import { EmptyState } from "@/components/ui/states";

function errText(err: unknown): string {
  if (err instanceof ApiError && typeof err.detail === "object" && err.detail !== null
    && "detail" in err.detail && typeof (err.detail as { detail: unknown }).detail === "string") {
    return (err.detail as { detail: string }).detail;
  }
  return "Unable to save case change.";
}

/** Analyst case management: status, assignment, notes, activity.
 *  Mutations refresh the parent investigation view on success. */
export function CaseSection({
  incidentId,
  caseState,
  onChanged,
}: {
  incidentId: string;
  caseState: InvestigationCase | null;
  onChanged: () => void;
}) {
  const [assignee, setAssignee] = useState("");
  const [note, setNote] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function mutate(fn: () => Promise<unknown>) {
    setPending(true);
    setError(null);
    try {
      await fn();
      setAssignee("");
      setNote("");
      onChanged();
    } catch (err) {
      setError(errText(err));
    } finally {
      setPending(false);
    }
  }

  if (caseState === null) {
    return <EmptyState message="Case state unavailable for this incident." />;
  }

  return (
    <div className="flex flex-col gap-4">
      {error && (
        <div role="alert" className="rounded border border-sev-high/50 bg-sev-high/10 p-3">
          <p className="text-sm font-medium text-sev-high">{error}</p>
        </div>
      )}
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs uppercase tracking-wide text-soc-muted">Status</span>
        <span className="font-mono text-sm text-white">{caseState.status}</span>
        <label className="text-xs text-soc-muted" htmlFor={`case-status-${incidentId}`}>
          Transition to
        </label>
        <select
          id={`case-status-${incidentId}`}
          className="rounded border border-soc-border bg-soc-panel px-2 py-1 text-sm text-soc-text"
          defaultValue=""
          disabled={pending || caseState.allowed_transitions.length === 0}
          onChange={(e) => {
            const target = e.target.value;
            if (target) void mutate(() => updateIncidentCase(incidentId, { status: target }));
            e.target.value = "";
          }}
        >
          <option value="">Select…</option>
          {caseState.allowed_transitions.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
        {caseState.allowed_transitions.length === 0 && (
          <span className="text-xs text-soc-muted">No further transitions (terminal state).</span>
        )}
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs uppercase tracking-wide text-soc-muted">Assignee</span>
        <span className="font-mono text-sm text-white">{caseState.assignee ?? "Unassigned"}</span>
        <label className="sr-only" htmlFor={`case-assignee-${incidentId}`}>Analyst identifier</label>
        <input
          id={`case-assignee-${incidentId}`}
          className="rounded border border-soc-border bg-soc-panel px-2 py-1 font-mono text-sm text-soc-text"
          placeholder="analyst-id"
          value={assignee}
          disabled={pending}
          onChange={(e) => setAssignee(e.target.value)}
        />
        <button
          type="button"
          disabled={pending || assignee.trim() === ""}
          onClick={() => void mutate(() => updateIncidentCase(incidentId, { assignee: assignee.trim() }))}
          className="rounded border border-soc-border px-2 py-1 text-sm text-soc-accent underline disabled:opacity-50"
        >
          Assign
        </button>
        {caseState.assignee !== null && (
          <button
            type="button"
            disabled={pending}
            onClick={() => void mutate(() => updateIncidentCase(incidentId, { assignee: null }))}
            className="rounded border border-soc-border px-2 py-1 text-sm text-soc-accent underline disabled:opacity-50"
          >
            Unassign
          </button>
        )}
      </div>

      <div>
        <p className="mb-1 text-xs uppercase tracking-wide text-soc-muted">
          Notes ({caseState.notes.length})
        </p>
        {caseState.notes.length === 0 ? (
          <p className="text-sm text-soc-muted">No analyst notes yet.</p>
        ) : (
          <ul className="flex flex-col gap-2">
            {caseState.notes.map((n) => (
              <li key={n.note_id} className="rounded border border-soc-border/60 p-2">
                <p className="text-sm text-soc-text">{n.body}</p>
                <p className="mt-1 font-mono text-xs text-soc-muted">
                  {n.author ?? "anonymous"} · {n.created_at}
                </p>
              </li>
            ))}
          </ul>
        )}
        <label className="sr-only" htmlFor={`case-note-${incidentId}`}>Add analyst note</label>
        <textarea
          id={`case-note-${incidentId}`}
          className="mt-2 w-full rounded border border-soc-border bg-soc-panel px-2 py-1 text-sm text-soc-text"
          rows={2}
          placeholder="Add an analyst note (plain text)…"
          value={note}
          disabled={pending}
          onChange={(e) => setNote(e.target.value)}
        />
        <button
          type="button"
          disabled={pending || note.trim() === ""}
          onClick={() => void mutate(() => createIncidentNote(incidentId, { body: note.trim() }))}
          className="mt-1 rounded border border-soc-border px-2 py-1 text-sm text-soc-accent underline disabled:opacity-50"
        >
          Add note
        </button>
      </div>

      <div>
        <p className="mb-1 text-xs uppercase tracking-wide text-soc-muted">
          Activity ({caseState.activity.length})
        </p>
        {caseState.activity.length === 0 ? (
          <p className="text-sm text-soc-muted">No recorded case activity yet.</p>
        ) : (
          <ul className="flex flex-col gap-1 font-mono text-xs">
            {caseState.activity.map((a) => (
              <li key={a.activity_id} className="text-soc-text">
                {a.created_at} · {a.action}
                {a.actor ? ` · by ${a.actor}` : ""}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

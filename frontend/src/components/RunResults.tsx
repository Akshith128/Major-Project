import { useEffect, useMemo, useState, type FormEvent } from 'react';
import { AlertTriangle } from 'lucide-react';
import { loadStoredRunResult, type StoredRunResult } from '../services/aegisService';
import { Panel, Stat } from './ui';

function valueOrDash(value: unknown): string {
  return value === null || value === undefined || value === '' ? '—' : String(value);
}

function statusTone(status: string): string {
  if (status === 'INTERRUPTED' || status === 'INCOMPLETE') return 'border-[#6B4F1A] bg-[#3A2A0C] text-warn';
  if (status === 'FAILED') return 'border-[#6B2A30] bg-[#3A1418] text-crit';
  return 'border-line-strong bg-panel-2 text-soft';
}

export function RunResults({ initialRunId }: { initialRunId: string }) {
  const [runId, setRunId] = useState(initialRunId);
  const [stored, setStored] = useState<StoredRunResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const load = async (requested: string) => {
    setLoading(true);
    setError(null);
    try {
      setStored(await loadStoredRunResult(requested));
    } catch (requestError) {
      setStored(null);
      setError(requestError instanceof Error ? requestError.message : 'Unable to load the stored run result.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load(initialRunId);
  }, [initialRunId]);

  const report = stored?.result;
  const riskMax = useMemo(
    () => Math.max(1, ...(report?.rows.map((r) => r.risk_score ?? 0) ?? [1])),
    [report]
  );

  const submit = (e: FormEvent) => {
    e.preventDefault();
    void load(runId);
  };

  return (
    <div className="flex flex-col gap-5">
      <Panel title="Stored run lookup" meta="GET /api/v1/runs/{run_id}/result">
        <form onSubmit={submit} className="flex flex-wrap items-end gap-3">
          <label className="flex min-w-0 flex-[1_1_320px] flex-col gap-2">
            <span className="font-mono text-xs uppercase tracking-[0.12em] text-muted">Run ID</span>
            <input
              value={runId}
              onChange={(e) => setRunId(e.target.value)}
              className="h-11 rounded-lg border border-line-strong bg-ink px-3 font-mono text-sm text-fg"
            />
          </label>
          <button type="submit" className="h-11 cursor-pointer rounded-lg bg-signal px-4 text-sm font-bold text-signal-ink">
            Load stored result
          </button>
        </form>
      </Panel>

      {loading && <p className="m-0 text-sm text-muted">Loading stored backend result…</p>}
      {error && (
        <p className="m-0 flex items-start gap-2 rounded-xl border border-[#6B4F1A] bg-[#3A2A0C] p-4 text-sm text-warn" role="alert">
          <AlertTriangle className="mt-0.5 h-4 w-4 flex-none" aria-hidden="true" />
          {error}
        </p>
      )}
      {!loading && !error && !report && (
        <p className="m-0 text-sm text-muted">The backend returned no stored result for this run.</p>
      )}

      {report && (
        <>
          <section className="flex flex-col gap-4">
            <div className="flex flex-wrap items-center gap-3">
              <span className={`rounded-full border px-3 py-1 font-mono text-xs font-bold ${statusTone(report.run_status)}`}>
                {report.run_status}
              </span>
              <span className="font-mono text-xs text-muted">
                {report.dataset} · [{report.pilot_start_row}, {report.pilot_end_row}) · batch {report.pilot_batch_size}
              </span>
            </div>
            {report.run_status === 'INTERRUPTED' && (
              <p className="m-0 text-sm text-warn">Interrupted: {valueOrDash(report.interruption_reason)}</p>
            )}
            <div className="grid grid-cols-1 gap-3.5 sm:grid-cols-2 xl:grid-cols-4">
              <Stat label="Completed" value={report.completed_window_count} />
              <Stat label="Partial" value={report.partial_window_count} />
              <Stat label="Incomplete" value={report.incomplete_window_count} />
              <Stat
                label="Final decision"
                value={<span className="text-base">{report.run_final_decision_code ?? 'Not produced'}</span>}
              />
            </div>
            <p className="m-0 text-sm text-soft">
              Missing predictions and a null final decision must not be read as benign or mitigated.
            </p>
          </section>

          <Panel title="Risk score by window">
            <div className="flex h-40 items-end gap-2 overflow-x-auto">
              {report.rows.map((row) => {
                const risk = row.risk_score ?? 0;
                return (
                  <div key={row.window} className="flex h-full min-w-8 flex-1 flex-col items-center justify-end gap-1.5">
                    <span
                      className="w-full max-w-12 rounded-t-md bg-warn/80"
                      style={{ height: `${Math.max(2, (risk / riskMax) * 100)}%` }}
                      title={`Window ${row.window}: risk ${risk}`}
                    />
                    <span className="font-mono text-xs text-muted">W{row.window}</span>
                  </div>
                );
              })}
            </div>
          </Panel>

          <Panel title="Window results" bodyClassName="overflow-x-auto">
            <table className="w-full min-w-[860px] border-collapse text-sm">
              <thead>
                <tr className="text-left font-mono text-[11px] uppercase tracking-wider text-muted">
                  {['Window', 'Ground truth', 'Monitoring', 'LLM', 'Risk', 'Severity', 'Verification', 'Status'].map((h) => (
                    <th key={h} className="px-4 py-3 font-medium">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {report.rows.map((row) => (
                  <tr key={row.window} className="border-t border-line align-top">
                    <td className="px-4 py-3 font-mono">W{row.window}</td>
                    <td className="px-4 py-3">
                      {valueOrDash(row.ground_truth_dominant_label)} ({valueOrDash(row.ground_truth_binary_class)})
                      <div className="mt-1 text-xs text-muted">
                        {Object.entries(row.label_counts ?? {})
                          .map(([label, count]) => `${label}: ${count}`)
                          .join(', ') || 'No counts'}
                      </div>
                    </td>
                    <td className="px-4 py-3 font-mono text-xs">{valueOrDash(row.monitoring_anomaly_prediction)}</td>
                    <td className="px-4 py-3 font-mono text-xs">{valueOrDash(row.llm_detection_prediction)}</td>
                    <td className="px-4 py-3 font-mono">{valueOrDash(row.risk_score)}</td>
                    <td className="px-4 py-3 font-mono text-xs">{valueOrDash(row.enforced_severity)}</td>
                    <td className="px-4 py-3 text-xs">{valueOrDash(row.verification_outcome)}</td>
                    <td className="px-4 py-3 font-mono text-xs">{row.window_status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Panel>
        </>
      )}
    </div>
  );
}

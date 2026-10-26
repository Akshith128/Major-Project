import { useEffect, useState } from 'react';
import { CheckCircle2, ShieldAlert, XCircle } from 'lucide-react';
import { api, type Metrics, type Run } from '../api';
import { EmptyState, Kicker, Panel, formatRatio } from './ui';

function MetricCard({ title, note, m }: { title: string; note: string; m: Metrics }) {
  return (
    <div className="flex flex-col gap-3 rounded-lg border border-line p-4">
      <div className="flex flex-col gap-1">
        <Kicker className="text-fg">{title}</Kicker>
        <span className="text-xs text-muted">{note}</span>
      </div>
      <div className="grid grid-cols-4 gap-2" aria-label={`${title} confusion matrix`}>
        {(
          [
            ['TP', m.tp, 'text-ok'],
            ['FP', m.fp, 'text-warn'],
            ['FN', m.fn, 'text-crit'],
            ['TN', m.tn, 'text-soft'],
          ] as const
        ).map(([k, v, tone]) => (
          <div key={k} className="rounded-lg border border-line bg-ink-raised px-2.5 py-2">
            <span className="font-mono text-[11px] text-muted">{k}</span>
            <span className={`block font-mono text-lg font-bold ${tone}`}>{v}</span>
          </div>
        ))}
      </div>
      <dl className="m-0 grid grid-cols-4 gap-2 text-center">
        {(
          [
            ['Precision', m.precision],
            ['Recall', m.recall],
            ['F1', m.f1],
            ['FPR', m.false_positive_rate],
          ] as const
        ).map(([k, v]) => (
          <div key={k}>
            <dt className="font-mono text-[11px] uppercase text-muted">{k}</dt>
            <dd className="m-0 font-mono text-sm text-signal">{formatRatio(v)}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

function AuditTrail({ run }: { run: Run }) {
  const [check, setCheck] = useState<{ valid: boolean; broken_at: number | null } | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setCheck(null);
    setError(null);
    api
      .verifyAudit(run.id)
      .then(setCheck)
      .catch((err) => setError(err instanceof Error ? err.message : 'Verification failed.'));
  }, [run.id, run.audit.length]);

  return (
    <Panel
      title="Tamper-evident audit trail"
      meta={`${run.audit.length} records · SHA-256 hash chain`}
      bodyClassName="flex flex-col gap-4 p-5"
    >
      {check && (
        <p role="status" className={`m-0 flex items-center gap-2 text-sm ${check.valid ? 'text-ok' : 'text-crit'}`}>
          {check.valid ? <CheckCircle2 className="h-4 w-4" aria-hidden="true" /> : <XCircle className="h-4 w-4" aria-hidden="true" />}
          {check.valid ? 'Chain verified — no record has been altered, removed or reordered.' : `Chain broken at record ${check.broken_at}.`}
        </p>
      )}
      {error && <p className="m-0 text-sm text-warn">{error}</p>}
      <div className="max-h-[480px] overflow-auto rounded-lg border border-line">
        <table className="w-full min-w-[640px] border-collapse text-sm">
          <thead className="sticky top-0 bg-panel">
            <tr className="text-left font-mono text-[11px] uppercase tracking-wider text-muted">
              <th className="px-4 py-2.5 font-medium">#</th>
              <th className="px-2 py-2.5 font-medium">Time</th>
              <th className="px-2 py-2.5 font-medium">Actor</th>
              <th className="px-2 py-2.5 font-medium">Action</th>
              <th className="px-4 py-2.5 font-medium">Hash</th>
            </tr>
          </thead>
          <tbody>
            {[...run.audit].reverse().map((r) => (
              <tr key={r.seq} className="border-t border-line align-top">
                <td className="px-4 py-2.5 font-mono text-muted">{r.seq}</td>
                <td className="px-2 py-2.5 font-mono text-xs text-soft">{new Date(r.at).toLocaleTimeString()}</td>
                <td className={`px-2 py-2.5 text-xs ${r.actor.startsWith('analyst:') ? 'text-signal' : 'text-soft'}`}>{r.actor}</td>
                <td className="px-2 py-2.5">
                  <span className="font-mono text-xs">{r.action}</span>
                  {'window' in r.detail && <span className="ml-2 text-xs text-muted">W{String(r.detail.window)}{r.detail.decision ? ` · ${String(r.detail.decision)}` : ''}</span>}
                </td>
                <td className="px-4 py-2.5 font-mono text-xs text-muted" title={r.hash}>{r.hash.slice(0, 12)}…</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}

export function Governance({ run, onOpen }: { run: Run | null; onOpen: (index: number) => void }) {
  if (!run) return <EmptyState>Governance evidence appears here after the first run.</EmptyState>;
  const queue = run.windows.filter((w) => w.governance.decision === 'PENDING_REVIEW' && !w.review);
  const reviewed = run.windows.filter((w) => w.review);

  return (
    <div className="flex flex-col gap-5">
      <section className="grid grid-cols-1 gap-4 md:grid-cols-3" aria-label="Digital trust guarantees">
        {[
          ['Human in the loop', `High-severity, low-confidence or rule-based responses wait for an analyst. ${queue.length} waiting, ${reviewed.length} reviewed.`],
          ['No silent actions', 'Responses are recommendations; nothing is executed without an approval on record.'],
          ['Labels isolated', 'Agents see only aggregate traffic features. Ground truth is used for evaluation after the run.'],
        ].map(([t, d]) => (
          <div key={t} className="flex flex-col gap-2 rounded-xl border border-line bg-panel p-5">
            <h3 className="m-0 text-base font-semibold">{t}</h3>
            <p className="m-0 text-sm text-soft">{d}</p>
          </div>
        ))}
      </section>

      <Panel title="Review queue" meta={`${queue.length} pending`} bodyClassName="p-2">
        {queue.length === 0 ? (
          <p className="m-0 p-3 text-sm text-muted">No responses waiting for review.</p>
        ) : (
          <ul className="m-0 flex list-none flex-col p-0">
            {queue.map((w) => (
              <li key={w.index}>
                <button type="button" onClick={() => onOpen(w.index)} className="flex w-full cursor-pointer items-start gap-3 rounded-lg px-3 py-3 text-left hover:bg-panel-2">
                  <ShieldAlert className="mt-0.5 h-4 w-4 flex-none text-warn" aria-hidden="true" />
                  <span className="flex min-w-0 flex-col gap-0.5">
                    <span className="text-sm font-semibold">
                      W{w.index} · {w.detection?.attack_type} · {w.risk?.severity}
                    </span>
                    <span className="text-xs text-muted">{w.governance.reasons.join(' · ')}</span>
                  </span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </Panel>

      {run.evaluation && (
        <Panel title="Evaluation against ground truth" meta="computed after the run">
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <MetricCard title="Monitoring gate" note="Deterministic triage alone" m={run.evaluation.monitoring} />
            <MetricCard title="Full agent pipeline" note="Monitoring + detection agent" m={run.evaluation.pipeline} />
          </div>
        </Panel>
      )}

      <AuditTrail run={run} />
    </div>
  );
}

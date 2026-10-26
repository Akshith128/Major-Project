import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { CheckCircle2, OctagonPause, Play, ShieldAlert, ShieldCheck, XCircle } from 'lucide-react';
import { api, type AuditCheck, type ControlState, type Evaluation, type Metrics, type Run } from '../api';
import { EmptyState, Panel, Stat, formatRatio } from './ui';

const DETECTOR_LABELS: Record<string, string> = {
  monitoring: 'Monitoring gate',
  pipeline: 'Full agent pipeline',
  random_forest: 'Random Forest (other days)',
  tcp_window_rule: 'TCP-window rule',
};

function interval(ci: [number, number] | null | undefined) {
  return ci ? <span className="block text-[11px] text-muted">[{ci[0].toFixed(2)}, {ci[1].toFixed(2)}]</span> : null;
}

/** Every detector scored on the same windows, with intervals and paired tests. */
function EvaluationPanel({ run, evaluation: ev }: { run: Run; evaluation: Evaluation }) {
  const rows: [string, Metrics][] = [
    ['monitoring', ev.monitoring],
    ['pipeline', ev.pipeline],
    ...(Object.entries(ev.baselines) as [string, Metrics][]),
  ];
  const rf = run.baselines?.random_forest;
  const cal = ev.calibration;
  const ops = ev.operations;
  const gov = ev.governance;
  const columns: [string, keyof Metrics, keyof Metrics['ci95'] | null][] = [
    ['MCC', 'mcc', 'mcc'],
    ['Bal. acc.', 'balanced_accuracy', null],
    ['F1', 'f1', 'f1'],
    ['Recall', 'recall', 'recall'],
    ['FPR', 'false_positive_rate', 'false_positive_rate'],
    ['Accuracy', 'accuracy', 'accuracy'],
  ];

  return (
    <Panel
      title="Evaluation against ground truth"
      meta={`${ev.pipeline.n} windows · attack prevalence ${formatRatio(ev.pipeline.prevalence)} · 95% CI`}
      bodyClassName="flex flex-col gap-5 p-5"
    >
      {ev.pipeline.n < 100 && (
        <p className="m-0 text-sm text-warn">
          {ev.pipeline.n} windows give wide intervals. For claims, use the multi-day benchmark: <code className="font-mono text-xs">python -m aegis.benchmark</code>
        </p>
      )}
      <div className="overflow-x-auto rounded-lg border border-line">
        <table className="w-full min-w-[720px] border-collapse text-sm">
          <thead>
            <tr className="text-left font-mono text-[11px] uppercase tracking-wider text-muted">
              <th className="px-4 py-2.5 font-medium">Detector</th>
              {columns.map(([label]) => (
                <th key={label} className="px-2 py-2.5 text-right font-medium">{label}</th>
              ))}
              <th className="px-4 py-2.5 text-right font-medium">TP / FP / FN / TN</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(([name, m]) => (
              <tr key={name} className={`border-t border-line align-top ${name === 'pipeline' ? 'bg-[#122631]' : ''}`}>
                <td className="px-4 py-2.5 font-semibold">{DETECTOR_LABELS[name] ?? name}</td>
                {columns.map(([label, key, ciKey]) => (
                  <td key={label} className="px-2 py-2.5 text-right font-mono">
                    {formatRatio(m[key] as number | null)}
                    {ciKey && m[key] != null && interval(m.ci95[ciKey])}
                  </td>
                ))}
                <td className="px-4 py-2.5 text-right font-mono text-xs text-soft">
                  {m.tp} / {m.fp} / {m.fn} / {m.tn}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {run.detector && (
        <p className="m-0 text-xs text-muted">
          Decided by a benign-trained anomaly detector ({run.detector.baseline} baseline: {run.detector.sources.join('; ')}),
          threshold set for a {Math.round(run.detector.false_alarm_budget * 100)}% false-alarm budget on normal traffic.
        </p>
      )}
      <p className="m-0 text-xs text-muted">
        {rf?.available
          ? `Random Forest trained on ${rf.training_flows?.toLocaleString()} flows from ${rf.trained_on?.length} other day-files — never on this run's day.`
          : `Random Forest: ${rf?.reason ?? 'not computed for this run.'}`}{' '}
        If the TCP-window rule matches the gate, the gate is mostly reading a testbed artefact.
      </p>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="flex flex-col gap-2 rounded-lg border border-line p-4">
          <h3 className="m-0 text-sm font-semibold">Paired comparisons (McNemar, exact)</h3>
          <ul className="m-0 flex list-none flex-col gap-1.5 p-0 text-sm text-soft">
            {ev.comparisons.map((c) => (
              <li key={`${c.a}-${c.b}`} className="flex flex-wrap justify-between gap-2">
                <span>
                  {DETECTOR_LABELS[c.a] ?? c.a} vs {DETECTOR_LABELS[c.b] ?? c.b}
                </span>
                <span className="font-mono text-xs">
                  {c.a_only_correct}:{c.b_only_correct} · p = {c.p_value}
                  {c.p_value < 0.05 ? <span className="text-signal"> significant</span> : ''}
                </span>
              </li>
            ))}
          </ul>
          <p className="m-0 text-xs text-muted">
            Monitoring score ROC-AUC {formatRatio(ev.monitoring_auc.roc_auc)} · PR-AUC {formatRatio(ev.monitoring_auc.pr_auc)}
          </p>
        </div>
        <div className="flex flex-col gap-2 rounded-lg border border-line p-4">
          <h3 className="m-0 text-sm font-semibold">Trust and cost</h3>
          <dl className="m-0 grid grid-cols-2 gap-x-4 gap-y-1.5 text-sm">
            {(
              [
                ['Confidence calibration (ECE)', cal.n ? `${formatRatio(cal.ece)} over ${cal.n} Gemini calls` : 'no Gemini decisions'],
                ['Accuracy at confidence ≥80 / <80', cal.n ? `${formatRatio(cal.accuracy_conf_ge_80)} / ${formatRatio(cal.accuracy_conf_lt_80)}` : '—'],
                ['Review load', formatRatio(gov.review_load)],
                ['Auto-approval precision', `${formatRatio(gov.auto_approval_precision)} (${gov.auto_approved_benign} benign auto-approved)`],
                ['Escalation recall', formatRatio(gov.escalation_recall)],
                ['Analyst override rate', `${formatRatio(gov.override_rate)} of ${gov.reviewed} reviewed`],
                ['LLM calls · fallback rate', `${ops.llm_calls} · ${formatRatio(ops.detection_fallback_rate)}`],
                ['Latency median / p95', ops.latency_ms_median != null ? `${ops.latency_ms_median} / ${ops.latency_ms_p95} ms` : '—'],
                ['Tokens per window', ops.tokens_per_window ?? '—'],
                ['Model versions', ops.model_versions.join(', ') || '—'],
              ] as const
            ).map(([k, v]) => (
              <div key={k} className="contents">
                <dt className="text-muted">{k}</dt>
                <dd className="m-0 font-mono text-xs leading-5 text-fg">{v}</dd>
              </div>
            ))}
          </dl>
        </div>
      </div>
    </Panel>
  );
}

function AuditTrail({ run }: { run: Run }) {
  const [check, setCheck] = useState<(AuditCheck & { at: Date }) | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);

  // Asks the API to recheck the stored file: hashes, HMAC signatures and the external checkpoint.
  const verify = useCallback(async () => {
    setChecking(true);
    setError(null);
    try {
      setCheck({ ...(await api.verifyAudit(run.id)), at: new Date() });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Verification failed.');
    } finally {
      setChecking(false);
    }
  }, [run.id]);

  useEffect(() => {
    setCheck(null);
    void verify();
  }, [verify, run.audit.length]);

  return (
    <Panel
      title="Tamper-evident audit trail"
      meta={`${run.audit.length} records · SHA-256 chain · HMAC-signed · external checkpoint`}
      bodyClassName="flex flex-col gap-4 p-5"
    >
      <div className="flex flex-wrap items-center gap-3">
        <button
          type="button"
          onClick={() => void verify()}
          disabled={checking}
          className="flex h-11 cursor-pointer items-center gap-2 rounded-lg bg-signal px-4 text-sm font-bold text-signal-ink disabled:cursor-not-allowed disabled:opacity-50"
        >
          <ShieldCheck className="h-4 w-4" aria-hidden="true" /> {checking ? 'Verifying…' : 'Verify chain'}
        </button>
        {check && (
          <p role="status" className={`m-0 flex flex-wrap items-center gap-2 text-sm ${check.valid ? 'text-ok' : 'text-crit'}`}>
            {check.valid ? <CheckCircle2 className="h-4 w-4" aria-hidden="true" /> : <XCircle className="h-4 w-4" aria-hidden="true" />}
            {check.valid
              ? `All ${check.records} records intact${check.signed ? ' and signed' : ''}${check.checkpoint_seq ? `; matches checkpoint #${check.checkpoint_seq}` : ''}.`
              : `${check.reason ?? 'Chain broken.'}${check.broken_at ? ` (record #${check.broken_at})` : ''}`}
            <span className="font-mono text-xs text-muted">checked {check.at.toLocaleTimeString()}</span>
          </p>
        )}
      </div>
      {check?.valid && !check.signed && (
        <p className="m-0 text-xs text-warn">
          {check.unsigned_records} record(s) predate signing: their hashes are checked, but a full rewrite of them would not be detected.
        </p>
      )}
      {error && <p role="alert" className="m-0 text-sm text-warn">{error}</p>}
      <div className="max-h-[480px] overflow-auto rounded-lg border border-line">
        <table className="w-full min-w-[640px] border-collapse text-sm">
          <thead className="sticky top-0 bg-panel">
            <tr className="text-left font-mono text-[11px] uppercase tracking-wider text-muted">
              <th className="px-4 py-2.5 font-medium">#</th>
              <th className="px-2 py-2.5 font-medium">Time</th>
              <th className="px-2 py-2.5 font-medium">Actor</th>
              <th className="px-2 py-2.5 font-medium">Action</th>
              <th className="px-2 py-2.5 font-medium">Prev</th>
              <th className="px-4 py-2.5 font-medium">Hash</th>
            </tr>
          </thead>
          <tbody>
            {[...run.audit].reverse().map((r) => (
              <tr key={r.seq} className={`border-t border-line align-top ${check && !check.valid && check.broken_at === r.seq ? 'bg-[#3A1418] text-crit' : ''}`}>
                <td className="px-4 py-2.5 font-mono text-muted">{r.seq}</td>
                <td className="px-2 py-2.5 font-mono text-xs text-soft">{new Date(r.at).toLocaleTimeString()}</td>
                <td className={`px-2 py-2.5 text-xs ${r.actor.startsWith('user:') || r.actor.startsWith('analyst:') ? 'text-signal' : 'text-soft'}`}>{r.actor}</td>
                <td className="px-2 py-2.5">
                  <span className="font-mono text-xs">{r.action}</span>
                  {'window' in r.detail && <span className="ml-2 text-xs text-muted">W{String(r.detail.window)}{r.detail.decision ? ` · ${String(r.detail.decision)}` : ''}</span>}
                </td>
                <td className="px-2 py-2.5 font-mono text-xs text-muted" title={r.prev_hash}>{r.prev_hash.slice(0, 10)}…</td>
                <td className="px-4 py-2.5 font-mono text-xs text-soft" title={r.mac ? `${r.hash}\nHMAC ${r.mac}` : r.hash}>
                  {r.hash.slice(0, 12)}…{!r.mac && <span className="ml-1 text-warn">unsigned</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}

/** EU AI Act Art. 14(4)(e): a stop button that halts the system in a safe state. */
function StopControl({
  control,
  canControl,
  onPause,
}: {
  control: ControlState | null;
  canControl: boolean;
  onPause: (paused: boolean, reason: string) => Promise<void>;
}) {
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const paused = !!control?.paused;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await onPause(!paused, reason);
      setReason('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not change the stop control.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Panel title="Stop control" meta={paused ? 'PAUSED' : 'running normally'}>
      <form onSubmit={submit} className="flex flex-col gap-3">
        <p className="m-0 text-sm text-soft">
          Pausing blocks new runs and stops a running one after its current window. Nothing is ever executed automatically, so the
          network is left as it is and pending recommendations stay pending.
        </p>
        {canControl ? (
          <div className="flex flex-wrap items-end gap-3">
            {!paused && (
              <label className="flex min-w-0 flex-[1_1_260px] flex-col gap-1.5 text-sm text-soft">
                Reason (recorded)
                <input value={reason} onChange={(e) => setReason(e.target.value)} maxLength={300} placeholder="e.g. Suspected model misbehaviour" className="h-11 rounded-lg border border-line-strong bg-ink px-3 text-sm text-fg" />
              </label>
            )}
            <button
              type="submit"
              disabled={busy}
              className={`flex h-11 cursor-pointer items-center gap-2 rounded-lg px-4 text-sm font-bold disabled:opacity-50 ${paused ? 'bg-ok text-[#062417]' : 'bg-crit text-[#2A0A0E]'}`}
            >
              {paused ? <Play className="h-4 w-4" aria-hidden="true" /> : <OctagonPause className="h-4 w-4" aria-hidden="true" />}
              {paused ? 'Resume AEGIS' : 'Pause AEGIS'}
            </button>
          </div>
        ) : (
          <p className="m-0 text-sm text-muted">Only a security manager can pause or resume AEGIS.</p>
        )}
        {error && <p role="alert" className="m-0 text-sm text-warn">{error}</p>}
      </form>
    </Panel>
  );
}

export function Governance({
  run,
  control,
  canControl,
  onPause,
  onOpen,
}: {
  run: Run | null;
  control: ControlState | null;
  canControl: boolean;
  onPause: (paused: boolean, reason: string) => Promise<void>;
  onOpen: (index: number) => void;
}) {
  const stop = <StopControl control={control} canControl={canControl} onPause={onPause} />;
  if (!run)
    return (
      <div className="flex flex-col gap-5">
        {stop}
        <EmptyState>Governance evidence appears here after the first run.</EmptyState>
      </div>
    );
  const queue = run.windows.filter((w) => w.governance.decision === 'PENDING_REVIEW' && !w.review);
  const reviewed = run.windows.filter((w) => w.review);
  const count = (d: string) => run.windows.filter((w) => w.governance.decision === d).length;
  const approved = reviewed.filter((w) => w.review?.decision === 'APPROVED').length;

  return (
    <div className="flex flex-col gap-5">
      <section aria-label="Governance decisions" className="grid grid-cols-1 gap-3.5 sm:grid-cols-2 xl:grid-cols-4">
        <Stat label="Pending review" value={queue.length} note="Needs an analyst decision" tone="text-warn" />
        <Stat label="Auto-approved" value={count('AUTO_APPROVED')} note={`Within policy ${run.windows[0]?.governance.policy ?? 'AEGIS-GOV-1'}`} tone="text-ok" />
        <Stat label="Analyst reviewed" value={reviewed.length} note={`${approved} approved · ${reviewed.length - approved} rejected`} tone="text-signal" />
        <Stat label="No action" value={count('NO_ACTION')} note="Clean or cleared windows" tone="text-soft" />
      </section>

      {stop}

      <section className="grid grid-cols-1 gap-4 md:grid-cols-3" aria-label="Digital trust guarantees">
        {[
          ['Human in the loop', `High-severity, low-confidence or rule-based responses wait for a signed-in reviewer. ${queue.length} waiting, ${reviewed.length} reviewed.`],
          ['No silent actions', 'Responses are recommendations; nothing is executed without an approval on record, and the stop control halts the system.'],
          ['Labels isolated', 'Agents see only aggregate traffic features. Ground truth and baselines are attached after the agents finish.'],
        ].map(([t, d]) => (
          <div key={t} className="flex flex-col gap-2 rounded-xl border border-line bg-panel p-5">
            <h3 className="m-0 text-base font-semibold">{t}</h3>
            <p className="m-0 text-sm text-soft">{d}</p>
          </div>
        ))}
      </section>

      {run.dataset_caution && (
        <p className="m-0 rounded-xl border border-[#6B4F1A] bg-[#2A1F0A] p-4 text-sm text-warn">
          <strong>Dataset caveat for this run:</strong> {run.dataset_caution}
        </p>
      )}

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

      {run.evaluation && 'baselines' in run.evaluation && <EvaluationPanel run={run} evaluation={run.evaluation} />}

      <AuditTrail run={run} />
    </div>
  );
}

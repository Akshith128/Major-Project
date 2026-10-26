import { useState, type ReactNode } from 'react';
import { Check, X } from 'lucide-react';
import type { Run, WindowResult } from '../api';
import { DecisionBadge, EmptyState, Kicker, Panel, SeverityBadge, SourceTag } from './ui';

type Filter = 'all' | 'threats' | 'review';

function Step({ name, source, children }: { name: string; source?: string; children: ReactNode }) {
  return (
    <li className="flex flex-col gap-2 border-l-2 border-line-strong py-1 pl-4">
      <div className="flex flex-wrap items-center gap-3">
        <span className="text-sm font-semibold">{name}</span>
        <SourceTag source={source} />
      </div>
      <div className="flex flex-col gap-1.5 text-sm text-soft">{children}</div>
    </li>
  );
}

function ReviewBox({ window: w, onReview }: { window: WindowResult; onReview: (decision: 'APPROVED' | 'REJECTED', note: string) => Promise<void> }) {
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const decide = async (decision: 'APPROVED' | 'REJECTED') => {
    setBusy(true);
    setError(null);
    try {
      await onReview(decision, note.trim());
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Review failed.');
    } finally {
      setBusy(false);
    }
  };

  if (w.review) {
    return (
      <p className={`m-0 text-sm ${w.review.decision === 'APPROVED' ? 'text-ok' : 'text-crit'}`}>
        {w.review.decision === 'APPROVED' ? 'Approved' : 'Rejected'} by {w.review.operator} · {new Date(w.review.at).toLocaleString()}
        {w.review.note && <span className="block text-soft">“{w.review.note}”</span>}
      </p>
    );
  }
  if (w.governance.decision !== 'PENDING_REVIEW') return null;
  return (
    <div className="flex flex-col gap-3 rounded-lg border border-[#6B4F1A] bg-ink-raised p-4">
      <label className="flex flex-col gap-2 text-sm font-semibold">
        Your decision on this response
        <textarea value={note} onChange={(e) => setNote(e.target.value)} rows={2} maxLength={500} placeholder="Optional note for the audit trail" className="rounded-lg border border-line-strong bg-ink p-3 text-sm font-normal text-fg placeholder:text-muted" />
      </label>
      <div className="flex flex-wrap gap-2.5">
        <button type="button" disabled={busy} onClick={() => decide('APPROVED')} className="flex h-11 cursor-pointer items-center gap-2 rounded-lg bg-ok px-4 text-sm font-bold text-[#062417] disabled:opacity-50">
          <Check className="h-4 w-4" aria-hidden="true" /> Approve response
        </button>
        <button type="button" disabled={busy} onClick={() => decide('REJECTED')} className="flex h-11 cursor-pointer items-center gap-2 rounded-lg border border-line-strong px-4 text-sm font-semibold text-fg hover:border-crit disabled:opacity-50">
          <X className="h-4 w-4" aria-hidden="true" /> Reject
        </button>
      </div>
      {error && <p role="alert" className="m-0 text-sm text-warn">{error}</p>}
    </div>
  );
}

function WindowDetail({ window: w, onReview }: { window: WindowResult; onReview: (decision: 'APPROVED' | 'REJECTED', note: string) => Promise<void> }) {
  const f = w.features;
  const shown: [string, string][] = [
    ['TCP share', `${Math.round(f.tcp_share * 100)}%`],
    ['Dominant signature', `${Math.round(f.dominant_signature_share * 100)}%`],
    ['TCP window diversity', f.unique_tcp_window_ratio.toFixed(2)],
    ['No-response flows', `${Math.round(f.no_response_share * 100)}%`],
    ['RST flows', `${Math.round(f.rst_share * 100)}%`],
    ['Packets / flow', f.mean_packets_per_flow.toFixed(1)],
  ];
  return (
    <Panel title={`Window ${w.index}`} meta={`rows ${w.row_start}–${w.row_end}`}>
      <div className="flex flex-col gap-5">
        <div className="flex flex-wrap items-center gap-2.5">
          <SeverityBadge severity={w.risk?.severity} />
          <DecisionBadge window={w} />
          {w.detection?.attack_type && <span className="text-sm font-semibold">{w.detection.attack_type}</span>}
        </div>

        <dl className="m-0 grid grid-cols-2 gap-2.5 sm:grid-cols-3">
          {shown.map(([k, v]) => (
            <div key={k} className="rounded-lg border border-line bg-ink-raised px-3 py-2">
              <dt className="text-xs text-muted">{k}</dt>
              <dd className="m-0 mt-0.5 font-mono text-base">{v}</dd>
            </div>
          ))}
        </dl>

        <div className="flex flex-col gap-3">
          <Kicker>Agent trace</Kicker>
          <ol className="m-0 flex list-none flex-col gap-3 p-0">
            <Step name="1 · Monitoring agent" source="rules">
              <span>
                Score <span className="font-mono text-fg">{w.monitoring.score}</span> vs gate {w.monitoring.threshold} →{' '}
                {w.monitoring.suspicious ? 'suspicious, sent to detection' : 'clear'}
              </span>
              {w.monitoring.signals.length > 0 && <span>{w.monitoring.signals.join(' · ')}</span>}
            </Step>
            {w.detection && (
              <Step name="2 · Detection agent" source={w.detection.source}>
                <span>
                  {w.detection.threat ? `Threat: ${w.detection.attack_type}` : 'No threat'} · confidence {w.detection.confidence}
                </span>
                <span>{w.detection.reasoning}</span>
                {w.detection.note && <span className="text-xs text-muted">Fallback reason: {w.detection.note}</span>}
              </Step>
            )}
            {w.risk && (
              <Step name="3 · Risk agent" source="rules">
                <span>
                  Risk <span className="font-mono text-fg">{w.risk.score}</span>/100 → {w.risk.severity}
                </span>
                <span>{w.risk.factors.join(' · ')}</span>
              </Step>
            )}
            {w.response && (
              <Step name="4 · Response agent" source={w.response.source}>
                <ol className="m-0 flex flex-col gap-1 pl-5">
                  {w.response.actions.map((a) => (
                    <li key={a}>{a}</li>
                  ))}
                </ol>
                {w.response.rationale && <span>{w.response.rationale}</span>}
                <span className="font-mono text-xs text-muted">Recommended — not executed automatically</span>
              </Step>
            )}
            <Step name={`${w.trace.length} · Governance agent`} source="rules">
              <span>{w.governance.reasons.join(' · ')}</span>
              <span className="font-mono text-xs text-muted">Policy {w.governance.policy}</span>
            </Step>
          </ol>
        </div>

        <ReviewBox window={w} onReview={onReview} />

        <p className="m-0 border-t border-line pt-3 text-xs text-muted">
          Ground truth (evaluation only, never shown to agents): {w.truth.dominant_label} · {Math.round(w.truth.attack_share * 100)}% attack flows
        </p>
      </div>
    </Panel>
  );
}

export function Incidents({
  run,
  selected,
  onSelect,
  onReview,
}: {
  run: Run | null;
  selected: number | null;
  onSelect: (index: number) => void;
  onReview: (index: number, decision: 'APPROVED' | 'REJECTED', note: string) => Promise<void>;
}) {
  const [filter, setFilter] = useState<Filter>('all');
  if (!run || run.windows.length === 0) return <EmptyState>Run the agents from the Overview to see incidents here.</EmptyState>;

  const rows = run.windows.filter((w) =>
    filter === 'threats' ? w.detection?.threat : filter === 'review' ? w.governance.decision === 'PENDING_REVIEW' && !w.review : true
  );
  const current = run.windows.find((w) => w.index === selected) ?? rows[0] ?? run.windows[0];
  const filters: [Filter, string][] = [
    ['all', `All (${run.windows.length})`],
    ['threats', `Threats (${run.windows.filter((w) => w.detection?.threat).length})`],
    ['review', `Needs review (${run.windows.filter((w) => w.governance.decision === 'PENDING_REVIEW' && !w.review).length})`],
  ];

  return (
    <div className="flex flex-wrap gap-5">
      <div className="flex min-w-0 flex-[999_1_520px] flex-col gap-3">
        <div className="flex flex-wrap gap-2" role="group" aria-label="Filter windows">
          {filters.map(([id, label]) => (
            <button key={id} type="button" aria-pressed={filter === id} onClick={() => setFilter(id)} className={`h-10 cursor-pointer rounded-full border px-4 text-sm ${filter === id ? 'border-signal bg-[#122631] text-fg' : 'border-line-strong text-soft hover:text-fg'}`}>
              {label}
            </button>
          ))}
        </div>
        <Panel bodyClassName="overflow-x-auto">
          {rows.length === 0 ? (
            <p className="m-0 p-5 text-sm text-muted">No windows match this filter.</p>
          ) : (
            <table className="w-full min-w-[620px] border-collapse text-sm">
              <thead>
                <tr className="text-left font-mono text-[11px] uppercase tracking-wider text-muted">
                  <th className="px-5 py-3 font-medium">Window</th>
                  <th className="px-2 py-3 text-right font-medium">Score</th>
                  <th className="px-2 py-3 font-medium">Detection</th>
                  <th className="px-2 py-3 font-medium">Severity</th>
                  <th className="px-5 py-3 font-medium">Governance</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((w) => {
                  const on = current?.index === w.index;
                  return (
                    <tr key={w.index} className={`border-t border-line ${on ? 'bg-[#122631]' : ''}`}>
                      <td className="px-5 py-2">
                        <button type="button" onClick={() => onSelect(w.index)} aria-current={on} className="cursor-pointer py-1.5 font-mono text-signal hover:underline">
                          W{w.index}
                        </button>
                      </td>
                      <td className="px-2 py-2 text-right font-mono">{w.monitoring.score.toFixed(2)}</td>
                      <td className="px-2 py-2">
                        {w.detection ? (w.detection.threat ? <span className="font-semibold text-crit">{w.detection.attack_type}</span> : <span className="text-ok">Cleared</span>) : <span className="text-muted">Not needed</span>}
                      </td>
                      <td className="px-2 py-2"><SeverityBadge severity={w.risk?.severity} /></td>
                      <td className="px-5 py-2"><DecisionBadge window={w} /></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </Panel>
      </div>
      {current && (
        <div className="min-w-0 flex-[1_1_400px]">
          <WindowDetail window={current} onReview={(decision, note) => onReview(current.index, decision, note)} />
        </div>
      )}
    </div>
  );
}

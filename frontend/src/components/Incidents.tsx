import { useState, type ReactNode } from 'react';
import { Check, X } from 'lucide-react';
import { LLM_SOURCES, type Provenance, type Run, type WindowResult } from '../api';
import type { OperatorRole } from '../lib/operator';
import { DecisionBadge, EmptyState, Kicker, Panel, SeverityBadge, SourceTag } from './ui';

type Filter = 'review' | 'threats' | 'reviewed' | 'all';

const isPending = (w: WindowResult) => w.governance.decision === 'PENDING_REVIEW' && !w.review;

/** How the pipeline's verdict compares with the hidden ground truth. */
function outcomeOf(w: WindowResult): { label: string; good: boolean } {
  const flagged = !!w.detection?.threat;
  if (flagged) return w.truth.is_attack ? { label: 'True positive', good: true } : { label: 'False positive', good: false };
  return w.truth.is_attack ? { label: 'False negative — attack missed', good: false } : { label: 'True negative', good: true };
}

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

/** One line that lets an examiner reproduce an LLM decision. */
function ProvenanceLine({ p }: { p?: Provenance }) {
  if (!p) return null;
  const tokens = p.tokens_in != null ? `${p.tokens_in}+${p.tokens_out ?? 0} tokens` : null;
  return (
    <span className="font-mono text-[11px] text-muted" title={`prompt ${p.prompt_sha256}\ninput ${p.input_sha256}`}>
      {[p.model_version ?? p.model, p.temperature != null && `temp ${p.temperature}`, p.latency_ms != null && `${p.latency_ms} ms`, tokens, `${p.prompt_template} · prompt ${p.prompt_sha256.slice(0, 10)}…`]
        .filter(Boolean)
        .join(' · ')}
      {p.schema_valid === false && <span className="text-warn"> · reply failed schema check</span>}
    </span>
  );
}

function ReviewBox({
  window: w,
  canReview,
  onReview,
}: {
  window: WindowResult;
  canReview: boolean;
  onReview: (decision: 'APPROVED' | 'REJECTED', note: string) => Promise<void>;
}) {
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
        {w.review.decision === 'APPROVED' ? 'Approved' : 'Rejected'} by {w.review.operator}
        {w.review.username && ` (${w.review.username})`} · {new Date(w.review.at).toLocaleString()}
        {w.review.note && <span className="block text-soft">“{w.review.note}”</span>}
      </p>
    );
  }
  if (w.governance.decision !== 'PENDING_REVIEW') return null;
  if (!canReview)
    return (
      <p className="m-0 rounded-lg border border-[#6B4F1A] bg-ink-raised p-4 text-sm text-warn">
        Awaiting approval by an analyst, responder or security manager. Your role can view it but not decide.
      </p>
    );
  return (
    <div className="flex flex-col gap-3 rounded-lg border border-[#6B4F1A] bg-ink-raised p-4">
      <label className="flex flex-col gap-2 text-sm font-semibold">
        Your approval is required before this response is executed
        <textarea value={note} onChange={(e) => setNote(e.target.value)} rows={2} maxLength={500} placeholder="Why you approve or reject — recorded in the audit trail" className="rounded-lg border border-line-strong bg-ink p-3 text-sm font-normal text-fg placeholder:text-muted" />
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

function WindowDetail({
  window: w,
  canReview,
  onReview,
}: {
  window: WindowResult;
  canReview: boolean;
  onReview: (decision: 'APPROVED' | 'REJECTED', note: string) => Promise<void>;
}) {
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
            <Step name={w.detector ? '1 · Monitoring · anomaly detector' : '1 · Monitoring agent'} source="rules">
              {w.detector ? (
                <>
                  <span>
                    Anomaly score <span className="font-mono text-fg">{w.detector.anomaly_score}</span> vs threshold {w.detector.threshold} →{' '}
                    {w.detector.anomalous ? 'abnormal, sent to the explaining agent' : 'within normal traffic'}
                  </span>
                  <span>Looks less normal than {w.detector.confidence}% of known-normal windows.</span>
                  {w.detector.similar_incidents.length > 0 && (
                    <span>
                      Similar known incidents:{' '}
                      {w.detector.similar_incidents.map((n) => `${n.family} (${n.day}, ${n.distance})`).join(' · ')}
                    </span>
                  )}
                </>
              ) : (
                <span>
                  Score <span className="font-mono text-fg">{w.monitoring.score}</span> vs gate {w.monitoring.threshold} →{' '}
                  {w.monitoring.suspicious ? 'suspicious, sent to detection' : 'clear'}
                </span>
              )}
              <span className="relative block h-1.5 max-w-xs rounded-full bg-panel-2" aria-hidden="true">
                <span className={`block h-full rounded-full ${w.monitoring.suspicious ? 'bg-warn' : 'bg-signal'}`} style={{ width: `${w.monitoring.score * 100}%` }} />
                <span className="absolute -top-1 h-3.5 w-0.5 bg-warn" style={{ left: `${w.monitoring.threshold * 100}%` }} />
              </span>
              {w.monitoring.signals.length > 0 && <span>{w.monitoring.signals.join(' · ')}</span>}
            </Step>
            {w.detection && (
              <Step name={w.detection.decided_by ? '2 · Detection · explaining agent' : '2 · Detection agent'} source={w.detection.source}>
                <span>
                  {w.detection.threat ? `Threat: ${w.detection.attack_type}` : 'No threat'} · confidence {w.detection.confidence}
                </span>
                <span>
                  {(LLM_SOURCES.includes(w.detection.source) || w.detection.source === 'hybrid') && (
                    <span className="mr-2 rounded border border-line-strong px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider text-muted">
                      Model rationale · not verified
                    </span>
                  )}
                  {w.detection.reasoning}
                </span>
                {w.detection.note && <span className="text-xs text-muted">Fallback reason: {w.detection.note}</span>}
                {w.detection.attack_techniques && w.detection.attack_techniques.length > 0 && (
                  <span>
                    MITRE ATT&CK: <span className="font-mono text-xs text-fg">{w.detection.attack_techniques.join(' · ')}</span>
                  </span>
                )}
                <ProvenanceLine p={w.detection.provenance} />
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
                <ProvenanceLine p={w.response.provenance} />
              </Step>
            )}
            <Step name={`${w.trace.length} · Governance agent`} source="rules">
              <span>{w.governance.reasons.join(' · ')}</span>
              <span className="font-mono text-xs text-muted">Policy {w.governance.policy}</span>
            </Step>
          </ol>
        </div>

        <ReviewBox key={w.index} window={w} canReview={canReview} onReview={onReview} />

        <p className="m-0 flex flex-wrap items-center gap-x-3 gap-y-1 border-t border-line pt-3 text-xs text-muted">
          <span>
            Ground truth (evaluation only, never shown to agents): {w.truth.dominant_label} · {Math.round(w.truth.attack_share * 100)}% attack flows
          </span>
          <span className={`font-mono font-bold uppercase ${outcomeOf(w).good ? 'text-ok' : 'text-crit'}`}>{outcomeOf(w).label}</span>
          {w.baselines?.random_forest && (
            <span>
              Random Forest baseline: {w.baselines.random_forest.attack ? 'attack' : 'benign'} ({Math.round(w.baselines.random_forest.attack_share * 100)}% of flows)
            </span>
          )}
          {w.baselines?.tcp_window_rule && <span>TCP-window rule: {w.baselines.tcp_window_rule.attack ? 'attack' : 'benign'}</span>}
        </p>
      </div>
    </Panel>
  );
}

export function Incidents({
  run,
  role,
  canReview,
  selected,
  onSelect,
  onReview,
}: {
  run: Run | null;
  role: OperatorRole;
  canReview: boolean;
  selected: number | null;
  onSelect: (index: number) => void;
  onReview: (index: number, decision: 'APPROVED' | 'REJECTED', note: string) => Promise<void>;
}) {
  // Responders land on their approval queue; everyone else starts from all windows.
  const [filter, setFilter] = useState<Filter>(role === 'responder' ? 'review' : 'all');
  if (!run || run.windows.length === 0) return <EmptyState>Run the agents from the Overview to see incidents here.</EmptyState>;

  const matches: Record<Filter, (w: WindowResult) => boolean> = {
    review: isPending,
    threats: (w) => !!w.detection?.threat,
    reviewed: (w) => !!w.review,
    all: () => true,
  };
  const rows = run.windows.filter(matches[filter]);
  if (role === 'responder') rows.sort((a, b) => Number(isPending(b)) - Number(isPending(a)));
  const current = run.windows.find((w) => w.index === selected) ?? rows[0] ?? run.windows[0];
  const filters: [Filter, string][] = [
    ['review', 'Awaiting review'],
    ['threats', 'Threats'],
    ['reviewed', 'Reviewed'],
    ['all', 'All windows'],
  ];

  return (
    <div className="flex flex-wrap gap-5">
      <div className="flex min-w-0 flex-[999_1_520px] flex-col gap-3">
        <div className="flex flex-wrap gap-2" role="group" aria-label="Filter windows">
          {filters.map(([id, label]) => (
            <button key={id} type="button" aria-pressed={filter === id} onClick={() => setFilter(id)} className={`h-10 cursor-pointer rounded-full border px-4 text-sm ${filter === id ? 'border-signal bg-[#122631] text-fg' : 'border-line-strong text-soft hover:text-fg'}`}>
              {label} <span className="font-mono opacity-80">{run.windows.filter(matches[id]).length}</span>
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
          <WindowDetail window={current} canReview={canReview} onReview={(decision, note) => onReview(current.index, decision, note)} />
        </div>
      )}
    </div>
  );
}

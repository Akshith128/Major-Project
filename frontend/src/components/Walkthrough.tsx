import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { Check, ChevronLeft, ChevronRight, Pause, Play, RotateCcw, X } from 'lucide-react';
import { LLM_SOURCES, providerName, type Run, type WindowResult } from '../api';
import { DecisionBadge, EmptyState, Kicker, Panel, SeverityBadge } from './ui';

interface Step {
  id: string;
  title: string;
  agent: string;
  caption: string;
  skipped?: string;
  body?: ReactNode;
}

const SPEEDS = { Slow: 4200, Normal: 2800, Fast: 1500 } as const;

/** Same mapping as aegis.evaluation.expected_attack_type: dataset label → attack family. */
function familyOf(label: string): string {
  const l = label.toLowerCase();
  if (l.startsWith('bot')) return 'Botnet';
  if (l.includes('ddos')) return 'DDoS';
  if (l.startsWith('dos')) return 'DoS';
  if (l.includes('infil')) return 'Infiltration';
  if (l.includes('-web') || l.includes('xss') || l.includes('sql')) return 'Web Attack';
  if (l.includes('brute')) return 'Brute Force';
  return 'Unknown';
}

function pct(value: number) {
  return `${Math.round(value * 100)}%`;
}

/** A bar that animates from 0 to `value` (0–1), with an optional threshold marker. */
function Gauge({ value, threshold, tone = 'bg-signal', label }: { value: number; threshold?: number; tone?: string; label?: string }) {
  return (
    <div className="flex flex-col gap-1.5">
      <div className="relative h-3 rounded-full bg-panel-2">
        <div className={`aegis-fill h-full rounded-full ${tone}`} style={{ width: `${Math.min(100, Math.max(2, value * 100))}%` }} />
        {threshold !== undefined && (
          <div className="absolute -top-1.5 h-6 w-0.5 bg-warn" style={{ left: `${threshold * 100}%` }} title={`threshold ${threshold}`} />
        )}
      </div>
      {label && <span className="font-mono text-xs text-muted">{label}</span>}
    </div>
  );
}

function Stagger({ items, delay = 220 }: { items: ReactNode[]; delay?: number }) {
  return (
    <>
      {items.map((item, i) => (
        <div key={i} className="aegis-fade-up" style={{ animationDelay: `${i * delay}ms` }}>
          {item}
        </div>
      ))}
    </>
  );
}

function Verdict({ ok, children }: { ok: boolean; children: ReactNode }) {
  return (
    <span
      className={`aegis-pop inline-flex items-center gap-2 self-start rounded-lg border px-3 py-1.5 text-sm font-bold ${
        ok ? 'border-ok-line bg-ok-soft text-ok' : 'border-warn-line bg-warn-soft text-warn'
      }`}
      style={{ animationDelay: '700ms' }}
    >
      {ok ? <Check className="h-4 w-4" aria-hidden="true" /> : <X className="h-4 w-4" aria-hidden="true" />}
      {children}
    </span>
  );
}

const KEY_FEATURES: [string, string][] = [
  ['tcp_share', 'TCP flows'],
  ['dominant_signature_share', 'Flows sharing one pattern'],
  ['rst_share', 'Flows reset'],
  ['no_response_share', 'Flows with no reply'],
  ['syn_share', 'SYN flows'],
  ['psh_share', 'Flows carrying data (PSH)'],
];

function buildSteps(run: Run, w: WindowResult): Step[] {
  const f = w.features;
  const d = w.detection;
  const steps: Step[] = [];

  steps.push({
    id: 'traffic',
    title: 'Traffic window',
    agent: 'Data',
    caption: `${f.flows} consecutive network flows (rows ${w.row_start}–${w.row_end}) are summarised into label-free numbers. The agents never see the attack labels.`,
    body: (
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <Stagger
          items={KEY_FEATURES.filter(([k]) => k in f).map(([k, label]) => (
            <Gauge key={k} value={f[k]} label={`${label}: ${pct(f[k])}`} />
          ))}
        />
        <div className="aegis-fade-up font-mono text-xs text-muted sm:col-span-2" style={{ animationDelay: '1200ms' }}>
          + {Object.keys(f).length - KEY_FEATURES.length - 1} more: packets per flow {f.mean_packets_per_flow}, packets/s {f.mean_packets_per_sec},
          mean duration {f.mean_flow_duration_ms} ms …
        </div>
      </div>
    ),
  });

  const det = w.detector;
  steps.push({
    id: 'monitoring',
    title: det ? 'Anomaly detector' : 'Monitoring gate',
    agent: 'Agent 1',
    caption: det
      ? det.memory
        ? 'Analysts have confirmed earlier incidents, so the incident memory decides: the window is an attack if it sits closer to a confirmed incident than to any normal traffic.'
        : 'A one-class SVM that learned only normal traffic scores how unusual this window is; it is flagged only if it is also uniform enough (homogeneity at least 0.6).'
      : 'A homogeneity score: attack traffic tends to repeat one flow pattern. At or above 0.6 the window goes to detection.',
    body: (
      <div className="flex flex-col gap-4">
        <Gauge
          value={w.monitoring.score}
          threshold={w.monitoring.threshold}
          tone={w.monitoring.suspicious ? 'bg-crit' : 'bg-signal'}
          label={`score ${w.monitoring.score} · threshold ${w.monitoring.threshold}${det ? ` · less normal than ${det.confidence}% of normal windows` : ''}`}
        />
        <div className="flex flex-col gap-1.5 text-sm text-soft">
          <Stagger items={w.monitoring.signals.map((s) => <span key={s}>• {s}</span>)} />
        </div>
        {det?.memory && (
          <div className="aegis-fade-up flex flex-wrap items-center gap-2 font-mono text-xs" style={{ animationDelay: '600ms' }}>
            <span className="rounded-lg border border-line-strong px-2.5 py-1.5">nearest normal window: d={det.memory.distance_to_normal}</span>
            <span className={`rounded-lg border px-2.5 py-1.5 ${det.memory.verdict.startsWith('matches') ? 'border-crit text-crit' : 'border-line-strong'}`}>
              nearest confirmed {det.memory.nearest_confirmed}: d={det.memory.distance_to_confirmed}
            </span>
            <span className="text-muted">→ decided by the incident memory ({det.memory.confirmed_incidents} confirmed incidents)</span>
          </div>
        )}
        <Verdict ok={!w.monitoring.suspicious}>{w.monitoring.suspicious ? 'Abnormal: sent on for analysis' : 'Normal traffic: no action needed'}</Verdict>
      </div>
    ),
  });

  const vote = d?.family_vote;
  steps.push({
    id: 'detection',
    title: vote ? 'Incident memory + explanation' : 'Detection',
    agent: 'Agent 2',
    caption: vote
      ? 'The family is named by a vote of the most similar known incidents (other days and analyst-confirmed ones). The language model only explains it.'
      : `The ${LLM_SOURCES.includes(d?.source ?? '') ? providerName(d?.source) + ' model' : 'rule fallback'} reads the numbers and decides whether this is an attack and which kind.`,
    skipped: d ? undefined : 'Skipped: the monitoring step found nothing unusual.',
    body: d && (
      <div className="flex flex-col gap-4">
        {vote && (
          <div className="flex flex-wrap items-center gap-3">
            <Stagger
              delay={350}
              items={vote.neighbours.map((n, i) => (
                <div key={i} className={`flex flex-col items-center gap-1 rounded-lg border px-3 py-2 text-center ${n.family === vote.family ? 'border-signal bg-signal-soft' : 'border-line-strong'}`}>
                  <span className="text-sm font-semibold">{n.family}</span>
                  <span className="font-mono text-[10px] text-muted">{n.source} · {n.day} · d={n.distance}</span>
                </div>
              ))}
            />
            <span className="aegis-fade-up font-mono text-sm text-muted" style={{ animationDelay: '1100ms' }}>
              → {vote.votes} agree
            </span>
          </div>
        )}
        <Verdict ok={!d.threat}>
          {d.threat ? `${d.attack_type}${d.attack_group ? ` · ${d.attack_group}` : ''} · confidence ${d.confidence}` : 'No threat'}
        </Verdict>
        {d.attack_techniques && d.attack_techniques.length > 0 && (
          <span className="aegis-fade-up font-mono text-xs text-soft" style={{ animationDelay: '900ms' }}>
            MITRE ATT&CK: {d.attack_techniques.join(' · ')}
          </span>
        )}
        <p className="aegis-fade-up m-0 text-sm leading-relaxed text-soft" style={{ animationDelay: '1200ms' }}>
          <span className="mr-2 rounded border border-line-strong px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider text-muted">
            {d.source === 'hybrid' || LLM_SOURCES.includes(d.source) ? 'Model rationale · not verified' : 'Rule-based'}
          </span>
          {d.reasoning}
        </p>
      </div>
    ),
  });

  const r = w.risk;
  steps.push({
    id: 'risk',
    title: 'Risk score',
    agent: 'Agent 3',
    caption: 'A fixed, auditable formula: (0.6 × confidence + 40 × score) × attack impact, plus a bonus for repeated attacks. The model may raise the severity, never lower it.',
    skipped: r ? undefined : 'Skipped: no threat was confirmed.',
    body: r && (
      <div className="flex flex-col gap-4">
        <div className="flex flex-col gap-1 text-sm text-soft">
          <Stagger items={r.factors.map((x) => <span key={x}>• {x}</span>)} />
        </div>
        <Gauge value={r.score / 100} tone={r.severity === 'CRITICAL' || r.severity === 'HIGH' ? 'bg-crit' : 'bg-warn'} label={`risk ${r.score} / 100`} />
        <span className="aegis-pop self-start" style={{ animationDelay: '900ms' }}>
          <SeverityBadge severity={r.severity} />
        </span>
      </div>
    ),
  });

  const resp = w.response;
  steps.push({
    id: 'response',
    title: 'Response plan',
    agent: 'Agent 4',
    caption: 'Containment actions are drafted from a per-attack playbook. They are only recommendations: nothing is executed automatically.',
    skipped: resp ? undefined : 'Skipped: nothing to contain.',
    body: resp && (
      <div className="flex flex-col gap-3">
        <ol className="m-0 flex flex-col gap-2 pl-5 text-sm">
          <Stagger delay={400} items={resp.actions.map((a) => <li key={a}>{a}</li>)} />
        </ol>
        <span className="aegis-fade-up font-mono text-xs text-warn" style={{ animationDelay: '1400ms' }}>
          RECOMMENDED · NOT EXECUTED
        </span>
      </div>
    ),
  });

  const g = w.governance;
  const checks: [string, boolean][] = d?.threat
    ? [
        ['Severity is LOW or MEDIUM', !(r && (r.severity === 'HIGH' || r.severity === 'CRITICAL'))],
        ['Confidence is at least 80', (d.confidence ?? 0) >= 80],
        ['A reasoning model was available (no fallback)', d.source === 'hybrid' || LLM_SOURCES.includes(d.source)],
      ]
    : [];
  steps.push({
    id: 'governance',
    title: 'Governance',
    agent: 'Agent 5',
    caption: `Policy ${g.policy}: a response is approved automatically only if every check passes; otherwise a signed-in analyst must approve or reject it.`,
    body: (
      <div className="flex flex-col gap-3">
        {checks.length > 0 ? (
          <Stagger
            delay={450}
            items={checks.map(([label, pass]) => (
              <span key={label} className={`flex items-center gap-2 text-sm ${pass ? 'text-ok' : 'text-warn'}`}>
                {pass ? <Check className="h-4 w-4" aria-hidden="true" /> : <X className="h-4 w-4" aria-hidden="true" />} {label}
              </span>
            ))}
          />
        ) : (
          <span className="text-sm text-soft">{g.reasons.join(' · ')}</span>
        )}
        <span className="aegis-pop self-start" style={{ animationDelay: '1500ms' }}>
          <DecisionBadge window={w} />
        </span>
        {w.review && (
          <span className="aegis-fade-up text-sm text-soft" style={{ animationDelay: '1800ms' }}>
            {w.review.decision === 'APPROVED' ? 'Approved' : 'Rejected'} by {w.review.operator}
            {w.review.family ? ` · family ${w.review.family}` : ''}
          </span>
        )}
      </div>
    ),
  });

  const record = run.audit.find((a) => a.action === 'WINDOW_DECIDED' && a.detail.window === w.index);
  steps.push({
    id: 'audit',
    title: 'Audit trail',
    agent: 'Ledger',
    caption: 'The decision is written to a hash chain: each record includes the previous record’s hash and is signed, so any later edit, deletion or reordering is detected.',
    body: record ? (
      <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
        <Stagger
          delay={500}
          items={[
            <div key="prev" className="rounded-lg border border-line-strong px-3 py-2 text-muted">
              #{record.seq - 1}
              <br />
              {record.prev_hash.slice(0, 12)}…
            </div>,
            <span key="arrow" className="text-signal">──▶</span>,
            <div key="this" className="aegis-pulse rounded-lg border border-signal bg-signal-soft px-3 py-2">
              #{record.seq} {record.action}
              <br />
              {record.hash.slice(0, 12)}…{record.mac ? ' · signed' : ''}
            </div>,
          ]}
        />
      </div>
    ) : (
      <span className="text-sm text-muted">Decision record not found in this run’s trail.</span>
    ),
  });

  const truthRight = (d?.threat ?? false) === w.truth.is_attack;
  steps.push({
    id: 'truth',
    title: 'Check against the truth',
    agent: 'Evaluation',
    caption: 'Only now, after the agents finished, are the dataset labels attached, to score the pipeline. They never influenced the decision.',
    body: (
      <div className="flex flex-col gap-3 text-sm">
        <Gauge value={w.truth.attack_share} tone="bg-crit" label={`${pct(w.truth.attack_share)} of flows are labelled attack · dominant label: ${w.truth.dominant_label}`} />
        <Verdict ok={truthRight}>
          {truthRight ? 'Pipeline was right' : 'Pipeline was wrong'} ·{' '}
          {d?.threat ? (w.truth.is_attack ? 'true positive' : 'false positive') : w.truth.is_attack ? 'missed attack' : 'true negative'}
        </Verdict>
        {d?.threat && w.truth.is_attack && (
          <span
            className={`aegis-fade-up ${familyOf(w.truth.dominant_label) === d.attack_type ? 'text-ok' : 'text-warn'}`}
            style={{ animationDelay: '800ms' }}
          >
            Family named {d.attack_type}; the labels say {familyOf(w.truth.dominant_label)} —{' '}
            {familyOf(w.truth.dominant_label) === d.attack_type ? 'correct.' : 'wrong.'}
            {familyOf(w.truth.dominant_label) !== d.attack_type && ['Botnet', 'Brute Force'].includes(familyOf(w.truth.dominant_label)) &&
              ' This family appears on only one day-file, so the memory had no example of it unless an analyst confirmed one.'}
          </span>
        )}
        {w.baselines?.random_forest && (
          <span className="aegis-fade-up text-soft" style={{ animationDelay: '1000ms' }}>
            For comparison, the Random Forest baseline said {w.baselines.random_forest.attack ? 'attack' : 'benign'}.
          </span>
        )}
      </div>
    ),
  });
  return steps;
}

export function Walkthrough({ run }: { run: Run | null }) {
  const [index, setIndex] = useState<number | null>(null);
  const [step, setStep] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState<keyof typeof SPEEDS>('Normal');

  const windows = run?.windows ?? [];
  const window = windows.find((w) => w.index === index) ?? windows.find((w) => w.detection?.threat) ?? windows[0];
  const steps = useMemo(() => (run && window ? buildSteps(run, window) : []), [run, window]);

  useEffect(() => {
    setStep(0);
  }, [window?.index, run?.id]);

  useEffect(() => {
    if (!playing) return;
    if (step >= steps.length - 1) {
      setPlaying(false);
      return;
    }
    const timer = window && steps[step]?.skipped ? SPEEDS[speed] / 2 : SPEEDS[speed];
    const id = setTimeout(() => setStep((s) => Math.min(s + 1, steps.length - 1)), timer);
    return () => clearTimeout(id);
  }, [playing, step, steps, speed, window]);

  if (!run || windows.length === 0 || !window) return <EmptyState>Run the agents first, then watch any window travel through the pipeline here.</EmptyState>;

  const current = steps[step];
  const choose = (i: number) => {
    setIndex(i);
    setStep(0);
    setPlaying(true);
  };

  return (
    <div className="flex flex-col gap-5">
      <p className="m-0 max-w-3xl text-soft">
        Pick a traffic window and press play to watch exactly what each agent did with it, using this run’s real data. Every number on
        screen is the one the system used.
      </p>

      <Panel title="Choose a window" meta={`${windows.length} windows in this run · red = threat flagged`} bodyClassName="flex flex-wrap gap-2 p-4">
        {windows.map((w) => {
          const on = w.index === window.index;
          return (
            <button
              key={w.index}
              type="button"
              aria-pressed={on}
              onClick={() => choose(w.index)}
              className={`h-9 min-w-11 cursor-pointer rounded-lg border px-2.5 font-mono text-xs font-semibold ${
                on ? 'border-signal bg-signal text-signal-ink' : w.detection?.threat ? 'border-crit-line bg-crit-soft text-crit' : 'border-line-strong bg-ink-raised text-soft hover:text-fg'
              }`}
            >
              W{w.index}
            </button>
          );
        })}
      </Panel>

      <section aria-label="Pipeline progress" className="aegis-glass rounded-xl border border-line p-4">
        <ol className="m-0 flex list-none items-center gap-0 overflow-x-auto p-0 pb-1">
          {steps.map((s, i) => {
            const state = i < step ? 'done' : i === step ? 'current' : 'pending';
            return (
              <li key={s.id} className="flex min-w-[96px] flex-1 items-center">
                <button
                  type="button"
                  onClick={() => {
                    setPlaying(false);
                    setStep(i);
                  }}
                  aria-current={state === 'current' ? 'step' : undefined}
                  className="flex w-full cursor-pointer flex-col items-center gap-1.5 text-center"
                >
                  <span
                    className={`flex h-9 w-9 items-center justify-center rounded-full border-2 font-mono text-xs font-bold transition-colors ${
                      s.skipped
                        ? 'border-dashed border-line-strong text-muted'
                        : state === 'current'
                          ? 'aegis-pulse border-signal bg-signal text-signal-ink'
                          : state === 'done'
                            ? 'border-signal bg-signal-soft text-signal'
                            : 'border-line-strong text-muted'
                    }`}
                  >
                    {state === 'done' && !s.skipped ? <Check className="h-4 w-4" aria-hidden="true" /> : i + 1}
                  </span>
                  <span className={`text-[11px] leading-tight ${state === 'current' ? 'font-semibold text-fg' : 'text-muted'}`}>{s.title}</span>
                </button>
                {i < steps.length - 1 && (
                  <span className="relative mx-1 mb-6 h-0.5 min-w-4 flex-1 bg-line-strong" aria-hidden="true">
                    {i < step && <span className="absolute inset-0 bg-signal" />}
                    {i === step - 1 && <span key={`${window.index}-${step}`} className="aegis-travel absolute -top-1 h-2.5 w-2.5 rounded-full bg-signal" />}
                  </span>
                )}
              </li>
            );
          })}
        </ol>
      </section>

      <Panel
        title={
          <span>
            W{window.index} · Step {step + 1} of {steps.length}: {current.title}
          </span>
        }
        meta={current.agent}
        bodyClassName="flex flex-col gap-5 p-5"
      >
        <div key={`${window.index}-${step}`} className="flex flex-col gap-5">
          <p className="aegis-fade-up m-0 max-w-3xl text-sm text-soft">{current.caption}</p>
          {current.skipped ? (
            <p className="aegis-fade-up m-0 rounded-lg border border-dashed border-line-strong p-4 text-sm text-muted">{current.skipped}</p>
          ) : (
            current.body
          )}
        </div>
        <div className="flex flex-wrap items-center gap-2 border-t border-line pt-4">
          <button type="button" onClick={() => { setPlaying(false); setStep((s) => Math.max(0, s - 1)); }} disabled={step === 0} aria-label="Previous step" className="flex h-11 w-11 cursor-pointer items-center justify-center rounded-lg border border-line-strong text-soft hover:text-fg disabled:cursor-not-allowed disabled:opacity-40">
            <ChevronLeft className="h-4 w-4" aria-hidden="true" />
          </button>
          <button
            type="button"
            onClick={() => {
              if (step >= steps.length - 1) setStep(0);
              setPlaying((p) => !p);
            }}
            className="flex h-11 cursor-pointer items-center gap-2 rounded-lg bg-signal px-4 text-sm font-bold text-signal-ink"
          >
            {playing ? <Pause className="h-4 w-4" aria-hidden="true" /> : <Play className="h-4 w-4" aria-hidden="true" />}
            {playing ? 'Pause' : step >= steps.length - 1 ? 'Replay' : 'Play'}
          </button>
          <button type="button" onClick={() => { setPlaying(false); setStep((s) => Math.min(steps.length - 1, s + 1)); }} disabled={step >= steps.length - 1} aria-label="Next step" className="flex h-11 w-11 cursor-pointer items-center justify-center rounded-lg border border-line-strong text-soft hover:text-fg disabled:cursor-not-allowed disabled:opacity-40">
            <ChevronRight className="h-4 w-4" aria-hidden="true" />
          </button>
          <button type="button" onClick={() => { setPlaying(false); setStep(0); }} aria-label="Restart" className="flex h-11 w-11 cursor-pointer items-center justify-center rounded-lg border border-line-strong text-soft hover:text-fg">
            <RotateCcw className="h-4 w-4" aria-hidden="true" />
          </button>
          <label className="ml-auto flex items-center gap-2 text-sm text-soft">
            Speed
            <select value={speed} onChange={(e) => setSpeed(e.target.value as keyof typeof SPEEDS)} className="h-10 rounded-lg border border-line-strong bg-ink px-2 text-sm text-fg">
              {Object.keys(SPEEDS).map((s) => (
                <option key={s}>{s}</option>
              ))}
            </select>
          </label>
        </div>
      </Panel>

      <Kicker>Each step uses the stored run data; nothing here is simulated.</Kicker>
    </div>
  );
}

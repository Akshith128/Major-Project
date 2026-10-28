import { useEffect, useState, type FormEvent } from 'react';
import { AlertTriangle, Play } from 'lucide-react';
import { datasetLabel, decisionScore, providerName, type Account, type Dataset, type Health, type Run, type RunConfig, type RunMode } from '../api';
import { can } from '../lib/operator';
import { DecisionBadge, EmptyState, Panel, SeverityBadge, Stat } from './ui';

const inputClass = 'h-11 w-full rounded-lg border border-line-strong bg-ink px-3 text-sm text-fg';
const labelClass = 'flex min-w-0 flex-col gap-2 font-mono text-xs uppercase tracking-[0.12em] text-muted';

// Mirrors RunRequest in aegis/api.py so the form rejects what the API would.
function validate(c: RunConfig): string | null {
  if (!c.dataset_id) return 'Pick a dataset. Place CIC-IDS2018 parquet files in data\\raw\\ if the list is empty.';
  if (!Number.isInteger(c.windows) || c.windows < 1 || c.windows > 200) return 'Windows must be a whole number between 1 and 200.';
  if (!Number.isInteger(c.window_size) || c.window_size < 10 || c.window_size > 5000) return 'Flows per window must be between 10 and 5000.';
  if (c.sampling === 'sequential' && (!Number.isInteger(c.start_row) || c.start_row < 0)) return 'Start row must be 0 or more.';
  return null;
}

const MODES: { id: RunMode; label: string; title: (llm: boolean) => string }[] = [
  { id: 'auto', label: 'Auto', title: (g) => (g ? 'Reasoning model, with rule fallback' : 'Rules (no reasoning model available)') },
  { id: 'llm', label: 'LLM', title: (g) => (g ? 'Force the reasoning model to decide' : 'No reasoning model available') },
  { id: 'rules', label: 'Rules', title: () => 'Deterministic thresholds only' },
  {
    id: 'hybrid',
    label: 'Hybrid',
    title: (g) => (g ? 'Anomaly detector decides; the reasoning model explains and plans' : 'Anomaly detector decides; no reasoning model, so explanations fall back'),
  },
];

function NewRunForm({
  datasets,
  health,
  busy,
  blocked,
  onStart,
}: {
  datasets: Dataset[];
  health: Health | null;
  busy: boolean;
  blocked: string | null;
  onStart: (config: RunConfig) => Promise<void>;
}) {
  const [config, setConfig] = useState<RunConfig>({
    dataset_id: '',
    windows: 10,
    window_size: 100,
    sampling: 'spread',
    start_row: 0,
    mode: 'auto',
  });
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const set = <K extends keyof RunConfig>(key: K, value: RunConfig[K]) => {
    setError(null);
    setConfig((c) => ({ ...c, [key]: value }));
  };

  useEffect(() => {
    const first = datasets.find((d) => !d.excluded_by_default) ?? datasets[0];
    if (!config.dataset_id && first) set('dataset_id', first.dataset_id);
  }, [datasets, config.dataset_id]);
  const chosen = datasets.find((d) => d.dataset_id === config.dataset_id);

  const llmReady = !!health?.llm.configured;
  const model = health ? `${providerName(health.llm.provider)} · ${health.llm.model}` : 'reasoning model';
  useEffect(() => {
    if (!llmReady && config.mode === 'llm') set('mode', 'auto');
  }, [llmReady, config.mode]);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const invalid = validate(config);
    if (invalid) return setError(invalid);
    setSubmitting(true);
    try {
      await onStart(config);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not start the run.');
    } finally {
      setSubmitting(false);
    }
  };

  const usesLlm = config.mode === 'llm' || (config.mode === 'auto' && llmReady);
  const plan =
    `${config.windows || 0} windows × ${config.window_size || 0} flows` +
    (config.dataset_id ? ` from ${datasetLabel(config.dataset_id)}` : '') +
    `, ${config.sampling === 'spread' ? 'spread across the capture' : `sequential from row ${config.start_row}`}` +
    (config.mode === 'hybrid'
      ? ` · a benign-trained anomaly detector decides (5% false-alarm budget); ${llmReady ? `${providerName(health?.llm.provider)} explains, maps to ATT&CK and plans` : 'no reasoning model, so families come from similar past incidents'}`
      : ` · detection by ${usesLlm ? `${providerName(health?.llm.provider)} (rule fallback on error)` : 'rules (score ≥ 0.75)'}`);

  return (
    <Panel title="Start a monitoring run" meta={llmReady ? `${model}${health?.llm.local ? ' · runs locally' : ''}` : health?.llm.note ?? 'No reasoning model · rules only'}>
      <form onSubmit={submit} noValidate className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-[2fr_repeat(4,minmax(0,1fr))_auto] lg:items-end">
        <label className={labelClass}>
          Dataset (CIC-IDS2018)
          <select value={config.dataset_id} onChange={(e) => set('dataset_id', e.target.value)} className={`${inputClass} font-sans normal-case tracking-normal`}>
            {datasets.length === 0 && <option value="">No datasets found</option>}
            {datasets.map((d) => (
              <option key={d.dataset_id} value={d.dataset_id}>
                {d.excluded_by_default ? '⚠ ' : ''}
                {datasetLabel(d.dataset_id)} · {d.rows.toLocaleString()} flows · {(d.attack_share * 100).toFixed(1)}% attack
              </option>
            ))}
          </select>
        </label>
        <label className={labelClass}>
          Windows
          <input type="number" min={1} max={200} value={config.windows} onChange={(e) => set('windows', e.target.valueAsNumber)} className={inputClass} />
        </label>
        <label className={labelClass}>
          Flows / window
          <input type="number" min={10} max={5000} value={config.window_size} onChange={(e) => set('window_size', e.target.valueAsNumber)} className={inputClass} />
        </label>
        <label className={labelClass}>
          Sampling
          <select value={config.sampling} onChange={(e) => set('sampling', e.target.value as RunConfig['sampling'])} className={`${inputClass} font-sans normal-case tracking-normal`}>
            <option value="spread">Spread across capture</option>
            <option value="sequential">Sequential</option>
          </select>
        </label>
        <fieldset className="m-0 flex min-w-0 flex-col gap-2 border-0 p-0">
          <legend className="mb-2 p-0 font-mono text-xs uppercase tracking-[0.12em] text-muted">Reasoning</legend>
          <div className="flex h-11 overflow-hidden rounded-lg border border-line-strong">
            {MODES.map((m) => {
              const on = config.mode === m.id;
              return (
                <button
                  key={m.id}
                  type="button"
                  aria-pressed={on}
                  disabled={m.id === 'llm' && !llmReady}
                  title={m.title(llmReady)}
                  onClick={() => set('mode', m.id)}
                  className={`flex-1 cursor-pointer text-[13px] font-semibold disabled:cursor-not-allowed disabled:opacity-40 ${on ? 'bg-signal text-signal-ink' : 'bg-ink text-soft hover:text-fg'}`}
                >
                  {m.label}
                </button>
              );
            })}
          </div>
        </fieldset>
        <button
          type="submit"
          disabled={busy || submitting || datasets.length === 0 || !!blocked}
          className="flex h-11 cursor-pointer items-center justify-center gap-2 rounded-lg bg-signal px-5 text-sm font-bold text-signal-ink disabled:cursor-not-allowed disabled:opacity-50"
        >
          <Play className="h-4 w-4" aria-hidden="true" /> {busy ? 'Running…' : submitting ? 'Starting…' : 'Run agents'}
        </button>
        {config.sampling === 'sequential' && (
          <label className={labelClass}>
            Start row
            <input type="number" min={0} value={config.start_row} onChange={(e) => set('start_row', e.target.valueAsNumber)} className={inputClass} />
          </label>
        )}
      </form>
      {chosen?.caution && (
        <p className={`m-0 mt-4 flex items-start gap-2 text-sm ${chosen.excluded_by_default ? 'text-warn' : 'text-soft'}`}>
          <AlertTriangle className="mt-0.5 h-4 w-4 flex-none text-warn" aria-hidden="true" />
          <span>
            <strong className="font-semibold text-fg">Dataset caveat:</strong> {chosen.caution}
          </span>
        </p>
      )}
      <div className="mt-4 flex flex-wrap gap-x-5 gap-y-2 text-sm">
        <span className="text-soft">{plan}</span>
        {blocked && <span className="text-warn">{blocked}</span>}
        {error && (
          <span role="alert" className="text-warn">
            {error}
          </span>
        )}
      </div>
    </Panel>
  );
}

function ScoreChart({ run, selected, onInspect }: { run: Run; selected: number | null; onInspect: (index: number) => void }) {
  const threshold = run.windows[0]?.monitoring.threshold ?? 0.6;
  const hybrid = run.windows.some((w) => w.detector?.decided_by === 'detector');
  return (
    <Panel
      title="Monitoring score by window"
      meta={`${hybrid ? 'lower of detector and homogeneity · ' : ''}gate ${threshold} · click a bar to inspect`}
    >
      {/* Bars sit above a 4px pad + 18px label + 6px gap, so the gate line starts 28px up. */}
      <div className="relative flex h-56 items-end gap-2 overflow-x-auto pb-1">
        <div
          aria-hidden="true"
          className="pointer-events-none absolute inset-x-0 border-t border-dashed border-warn/60"
          style={{ bottom: `calc(28px + ${threshold} * (100% - 28px))` }}
        />
        {run.windows.map((w) => {
          const threat = w.detection?.threat;
          const score = decisionScore(w);
          return (
            <button
              key={w.index}
              type="button"
              onClick={() => onInspect(w.index)}
              aria-label={`Window ${w.index}: score ${score.toFixed(2)}, ${threat ? 'threat' : 'clear'}`}
              className="group flex h-full min-w-9 flex-1 cursor-pointer flex-col items-center justify-end gap-1.5"
            >
              <span className="flex w-full flex-1 items-end justify-center">
                <span
                  className={`w-full max-w-14 rounded-t-md group-hover:brightness-125 ${threat ? 'bg-crit' : w.monitoring.suspicious ? 'bg-warn/70' : 'bg-signal/50'} ${w.index === selected ? 'outline-2 outline-offset-2 outline-fg' : ''}`}
                  style={{ height: `${Math.max(3, score * 100)}%` }}
                />
              </span>
              <span className="h-[18px] font-mono text-xs text-muted">W{w.index}</span>
            </button>
          );
        })}
      </div>
      <div className="mt-3 flex flex-wrap gap-4 text-xs text-muted">
        <span className="flex items-center gap-2"><span className="h-2.5 w-2.5 rounded-sm bg-crit" /> Threat confirmed by detection</span>
        <span className="flex items-center gap-2"><span className="h-2.5 w-2.5 rounded-sm bg-warn/70" /> Suspicious, cleared by detection</span>
        <span className="flex items-center gap-2"><span className="h-2.5 w-2.5 rounded-sm bg-signal/50" /> Below monitoring gate</span>
        <span className="flex items-center gap-2"><span className="w-4 border-t border-dashed border-warn" /> Gate {threshold}</span>
      </div>
    </Panel>
  );
}

export function Overview({
  run,
  account,
  paused,
  datasets,
  health,
  selected,
  onStart,
  onInspect,
}: {
  run: Run | null;
  account: Account;
  paused: boolean;
  datasets: Dataset[];
  health: Health | null;
  selected: number | null;
  onStart: (config: RunConfig) => Promise<void>;
  onInspect: (index: number) => void;
}) {
  const role = account.role;
  const running = run?.status === 'RUNNING';
  const blocked = paused
    ? 'AEGIS is halted; a security manager must resume it first.'
    : can(account, 'run')
      ? null
      : `${account.role_label}s can view runs but not start them.`;
  const threats = run?.windows.filter((w) => w.detection?.threat) ?? [];
  const pending = threats.filter((w) => w.governance.decision === 'PENDING_REVIEW' && !w.review);
  const focus = role === 'responder' ? pending : threats;
  const attackTypes = [...new Set(threats.map((w) => w.detection?.attack_type).filter(Boolean))];

  return (
    <div className="flex flex-col gap-6">
      <NewRunForm datasets={datasets} health={health} busy={running} blocked={blocked} onStart={onStart} />

      {!run ? (
        <EmptyState>No runs yet. Pick a dataset and run the agents — each window flows through monitoring, detection, risk, response and governance.</EmptyState>
      ) : (
        <>
          {running && (
            <div className="flex flex-col gap-2" role="status">
              <span className="font-mono text-xs text-signal">
                <span className="aegis-shimmer-text">AGENTS RUNNING</span> · window {run.progress.done}/{run.progress.total}
                {run.windows.length > 0 && ` · last W${run.windows[run.windows.length - 1].index} → ${run.windows[run.windows.length - 1].trace.join(' → ')}`}
              </span>
              <div className="h-1.5 overflow-hidden rounded-full bg-panel-2">
                <div className="h-full bg-signal transition-[width]" style={{ width: `${(run.progress.done / Math.max(1, run.progress.total)) * 100}%` }} />
              </div>
            </div>
          )}
          {run.error && (
            <p role="alert" className="m-0 rounded-xl border border-crit-line bg-crit-soft p-4 text-sm text-crit">
              Run {run.status === 'STOPPED' ? 'stopped' : 'failed'}: {run.error}
              {run.error.includes('restart') && ' Start the run again from the form above.'}
            </p>
          )}

          <section aria-label="Run indicators" className="aegis-stagger grid grid-cols-1 gap-3.5 sm:grid-cols-2 xl:grid-cols-4">
            <Stat label="Windows analysed" value={run.windows.length} note={`${run.config.window_size} flows each`} />
            <Stat label="Flagged by monitoring" value={run.windows.filter((w) => w.monitoring.suspicious).length} note="Sent to detection agent" tone="text-warn" />
            <Stat label="Threats detected" value={threats.length} note={attackTypes.join(', ') || 'None'} tone="text-crit" />
            <Stat label="Awaiting review" value={pending.length} note="Human-in-the-loop approvals" tone="text-signal" />
          </section>

          <div className="flex flex-wrap gap-5">
            <div className="min-w-0 flex-[999_1_560px]">
              {run.windows.length > 0 ? <ScoreChart run={run} selected={selected} onInspect={onInspect} /> : <EmptyState>Agents are analysing the first window…</EmptyState>}
            </div>
            <Panel title={role === 'responder' ? 'Waiting for your approval' : 'Detected threats'} meta="for you" className="flex-[1_1_320px]" bodyClassName="p-2">
              {focus.length === 0 ? (
                <p className="m-0 p-3 text-sm text-muted">{running ? 'Agents are still working…' : 'Nothing here for this run.'}</p>
              ) : (
                <ul className="m-0 flex list-none flex-col p-0">
                  {focus.map((w) => (
                    <li key={w.index}>
                      <button type="button" onClick={() => onInspect(w.index)} className="flex w-full cursor-pointer items-center justify-between gap-3 rounded-lg px-3 py-3 text-left hover:bg-panel-2">
                        <span className="flex min-w-0 flex-col gap-0.5">
                          <span className="text-sm font-semibold">W{w.index} · {w.detection?.attack_type}</span>
                          <span className="truncate text-xs text-muted">{w.response?.actions[0]}</span>
                        </span>
                        <span className="flex flex-none flex-col items-end gap-1">
                          <SeverityBadge severity={w.risk?.severity} />
                          <DecisionBadge window={w} />
                        </span>
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </Panel>
          </div>
        </>
      )}
    </div>
  );
}

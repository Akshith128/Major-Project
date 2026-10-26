import { useEffect, useState, type FormEvent } from 'react';
import { Play } from 'lucide-react';
import { datasetLabel, type Dataset, type Health, type Run, type RunConfig } from '../api';
import type { OperatorRole } from '../lib/operator';
import { DecisionBadge, EmptyState, Panel, SeverityBadge, Stat } from './ui';

const inputClass = 'h-11 w-full rounded-lg border border-line-strong bg-ink px-3 text-sm text-fg';
const labelClass = 'flex min-w-0 flex-col gap-2 font-mono text-xs uppercase tracking-[0.12em] text-muted';

function NewRunForm({
  datasets,
  health,
  busy,
  onStart,
}: {
  datasets: Dataset[];
  health: Health | null;
  busy: boolean;
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
  const set = <K extends keyof RunConfig>(key: K, value: RunConfig[K]) => setConfig((c) => ({ ...c, [key]: value }));

  useEffect(() => {
    if (!config.dataset_id && datasets.length) set('dataset_id', datasets[0].dataset_id);
  }, [datasets, config.dataset_id]);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      await onStart(config);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not start the run.');
    }
  };

  const gemini = health?.gemini.configured;
  return (
    <Panel title="Start a monitoring run" meta={gemini ? `Gemini · ${health?.gemini.model}` : 'Gemini not configured · rules only'}>
      <form onSubmit={submit} className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-[2fr_repeat(4,minmax(0,1fr))_auto] lg:items-end">
        <label className={labelClass}>
          Dataset (CIC-IDS2018)
          <select value={config.dataset_id} onChange={(e) => set('dataset_id', e.target.value)} className={`${inputClass} font-sans normal-case tracking-normal`} required>
            {datasets.map((d) => (
              <option key={d.dataset_id} value={d.dataset_id}>
                {datasetLabel(d.dataset_id)} · {d.rows.toLocaleString()} flows
              </option>
            ))}
          </select>
        </label>
        <label className={labelClass}>
          Windows
          <input type="number" min={1} max={200} value={config.windows} onChange={(e) => set('windows', Number(e.target.value))} className={inputClass} />
        </label>
        <label className={labelClass}>
          Flows / window
          <input type="number" min={10} max={5000} value={config.window_size} onChange={(e) => set('window_size', Number(e.target.value))} className={inputClass} />
        </label>
        <label className={labelClass}>
          Sampling
          <select value={config.sampling} onChange={(e) => set('sampling', e.target.value as RunConfig['sampling'])} className={`${inputClass} font-sans normal-case tracking-normal`}>
            <option value="spread">Spread across capture</option>
            <option value="sequential">Sequential</option>
          </select>
        </label>
        <label className={labelClass}>
          Reasoning
          <select value={config.mode} onChange={(e) => set('mode', e.target.value as RunConfig['mode'])} className={`${inputClass} font-sans normal-case tracking-normal`}>
            <option value="auto">Auto</option>
            <option value="gemini" disabled={!gemini}>Gemini</option>
            <option value="rules">Rules only</option>
          </select>
        </label>
        <button
          type="submit"
          disabled={busy || !config.dataset_id}
          className="flex h-11 cursor-pointer items-center justify-center gap-2 rounded-lg bg-signal px-5 text-sm font-bold text-signal-ink disabled:cursor-not-allowed disabled:opacity-50"
        >
          <Play className="h-4 w-4" aria-hidden="true" /> {busy ? 'Running…' : 'Run agents'}
        </button>
        {config.sampling === 'sequential' && (
          <label className={labelClass}>
            Start row
            <input type="number" min={0} value={config.start_row} onChange={(e) => set('start_row', Number(e.target.value))} className={inputClass} />
          </label>
        )}
      </form>
      {error && (
        <p role="alert" className="m-0 mt-4 text-sm text-warn">
          {error}
        </p>
      )}
    </Panel>
  );
}

function ScoreChart({ run, onInspect }: { run: Run; onInspect: (index: number) => void }) {
  const threshold = run.windows[0]?.monitoring.threshold ?? 0.6;
  return (
    <Panel title="Monitoring score by window" meta={`gate ${threshold} · click a bar to inspect`}>
      <div className="flex h-52 items-end gap-2 overflow-x-auto pb-1">
        {run.windows.map((w) => {
          const threat = w.detection?.threat;
          return (
            <button
              key={w.index}
              type="button"
              onClick={() => onInspect(w.index)}
              aria-label={`Window ${w.index}: score ${w.monitoring.score}, ${threat ? 'threat' : 'clear'}`}
              className="group flex h-full min-w-9 flex-1 cursor-pointer flex-col items-center justify-end gap-1.5"
            >
              <span className="flex w-full flex-1 items-end justify-center">
                <span className={`w-full max-w-14 rounded-t-md group-hover:brightness-125 ${threat ? 'bg-crit' : w.monitoring.suspicious ? 'bg-warn/70' : 'bg-signal/50'}`} style={{ height: `${Math.max(3, w.monitoring.score * 100)}%` }} />
              </span>
              <span className="font-mono text-xs text-muted">W{w.index}</span>
            </button>
          );
        })}
      </div>
      <div className="mt-3 flex flex-wrap gap-4 text-xs text-muted">
        <span className="flex items-center gap-2"><span className="h-2.5 w-2.5 rounded-sm bg-crit" /> Threat confirmed by detection</span>
        <span className="flex items-center gap-2"><span className="h-2.5 w-2.5 rounded-sm bg-warn/70" /> Suspicious, cleared by detection</span>
        <span className="flex items-center gap-2"><span className="h-2.5 w-2.5 rounded-sm bg-signal/50" /> Below monitoring gate</span>
      </div>
    </Panel>
  );
}

export function Overview({
  run,
  role,
  datasets,
  health,
  onStart,
  onInspect,
}: {
  run: Run | null;
  role: OperatorRole;
  datasets: Dataset[];
  health: Health | null;
  onStart: (config: RunConfig) => Promise<void>;
  onInspect: (index: number) => void;
}) {
  const running = run?.status === 'RUNNING';
  const s = run?.summary;
  const threats = run?.windows.filter((w) => w.detection?.threat) ?? [];
  const pending = threats.filter((w) => w.governance.decision === 'PENDING_REVIEW' && !w.review);
  const focus = role === 'responder' ? pending : threats;

  return (
    <div className="flex flex-col gap-6">
      <NewRunForm datasets={datasets} health={health} busy={running} onStart={onStart} />

      {!run ? (
        <EmptyState>No runs yet. Pick a dataset and run the agents.</EmptyState>
      ) : (
        <>
          {running && (
            <div className="flex flex-col gap-2" role="status">
              <span className="font-mono text-xs text-signal">
                AGENTS RUNNING · window {run.progress.done}/{run.progress.total}
              </span>
              <div className="h-1.5 overflow-hidden rounded-full bg-panel-2">
                <div className="h-full bg-signal transition-[width]" style={{ width: `${(run.progress.done / Math.max(1, run.progress.total)) * 100}%` }} />
              </div>
            </div>
          )}
          {run.error && (
            <p role="alert" className="m-0 rounded-xl border border-[#6B2A30] bg-[#3A1418] p-4 text-sm text-crit">
              Run failed: {run.error}
            </p>
          )}

          <section aria-label="Run indicators" className="grid grid-cols-1 gap-3.5 sm:grid-cols-2 xl:grid-cols-4">
            <Stat label="Windows analysed" value={run.windows.length} note={`${run.config.window_size} flows each`} />
            <Stat label="Flagged by monitoring" value={s?.suspicious ?? run.windows.filter((w) => w.monitoring.suspicious).length} note="Sent to detection agent" tone="text-warn" />
            <Stat label="Threats detected" value={s?.threats ?? threats.length} note={Object.keys(s?.attack_types ?? {}).join(', ') || 'None'} tone="text-crit" />
            <Stat label="Awaiting review" value={s?.pending_review ?? pending.length} note="Human-in-the-loop approvals" tone="text-signal" />
          </section>

          <div className="flex flex-wrap gap-5">
            <div className="min-w-0 flex-[999_1_560px]">
              <ScoreChart run={run} onInspect={onInspect} />
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

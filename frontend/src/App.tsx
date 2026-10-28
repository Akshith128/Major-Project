import { useCallback, useEffect, useState } from 'react';
import { AlertTriangle, LogOut, OctagonPause } from 'lucide-react';
import {
  api,
  datasetLabel,
  providerName,
  onSessionExpired,
  type Account,
  type ControlState,
  type Dataset,
  type Health,
  type Run,
  type RunConfig,
  type RunListItem,
  type Session,
} from './api';
import { PAGES, can, clearSession, greetingFor, initialsOf, readSession, roleSpec, saveSession, type ConsolePage } from './lib/operator';
import { Onboarding } from './components/Onboarding';
import { Overview } from './components/Overview';
import { Incidents } from './components/Incidents';
import { Governance } from './components/Governance';
import { Agents } from './components/Agents';
import { Walkthrough } from './components/Walkthrough';
import { Kicker, ShieldMark, SkeletonPage, ThemeToggle } from './components/ui';

const PROJECT_TITLE = 'Agentic AI for Autonomous Threat Detection and Response';
const PROJECT_SUBTITLE = 'Enhancing Cybersecurity Governance and Digital Trust';

export default function App() {
  const [account, setAccount] = useState<Account | null>(() => readSession()?.user ?? null);
  const [page, setPage] = useState<ConsolePage>(() => (account ? roleSpec(account.role).landing : 'overview'));
  const [control, setControl] = useState<ControlState | null>(null);

  const [health, setHealth] = useState<Health | null>(null);
  const [apiError, setApiError] = useState<string | null>(null);
  const [datasets, setDatasets] = useState<Dataset[]>([]);
  const [runs, setRuns] = useState<RunListItem[]>([]);
  const [runId, setRunId] = useState<string | null>(null);
  const [run, setRun] = useState<Run | null>(null);
  const [selected, setSelected] = useState<number | null>(null);

  const connect = useCallback(async () => {
    try {
      const [h, d, r, c] = await Promise.all([api.health(), api.datasets(), api.runs(), api.control()]);
      setHealth(h);
      setDatasets(d);
      setRuns(r);
      setControl(c);
      setRunId((current) => current ?? r[0]?.id ?? null);
      setApiError(null);
    } catch (err) {
      setApiError(err instanceof Error ? err.message : 'API unavailable');
    }
  }, []);

  const signOut = useCallback(() => {
    clearSession();
    setAccount(null);
    setRunId(null);
    setRun(null);
    setRuns([]);
  }, []);

  useEffect(() => onSessionExpired(signOut), [signOut]);

  useEffect(() => {
    if (account) void connect();
  }, [account, connect]);

  // Load the selected run; poll while the agents are still working on it.
  useEffect(() => {
    if (!runId) return;
    let cancelled = false;
    let timer: number | undefined;
    const load = async () => {
      try {
        const next = await api.run(runId);
        if (cancelled) return;
        setRun(next);
        if (next.status === 'RUNNING') timer = window.setTimeout(load, 1200);
        else {
          setRuns(await api.runs());
          setControl(await api.control());
        }
      } catch (err) {
        if (!cancelled) setApiError(err instanceof Error ? err.message : 'Could not load run');
      }
    };
    void load();
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [runId]);

  const enter = (session: Session, remember: boolean) => {
    saveSession(session, remember);
    setAccount(session.user);
    setPage(roleSpec(session.user.role).landing);
  };

  const operatorName = account?.name || 'Operator';

  const setPaused = async (paused: boolean, reason: string) => {
    setControl(await api.setPaused(paused, reason));
    if (runId) setRun(await api.run(runId));
  };

  const startRun = async (config: RunConfig) => {
    const started = await api.startRun(config);
    setSelected(null);
    setRun(null);
    setRunId(started.id);
    setRuns(await api.runs());
  };

  const review = async (index: number, decision: 'APPROVED' | 'REJECTED', note: string, family?: string) => {
    if (!run) return;
    await api.review(run.id, index, decision, note, family);
    setRun(await api.run(run.id));
  };

  const inspect = (index: number) => {
    setSelected(index);
    setPage('incidents');
  };

  if (!account) return <Onboarding onSignedIn={enter} />;

  const role = roleSpec(account.role);

  return (
    <div className="flex min-h-screen flex-col">
      <header className="aegis-header sticky top-0 z-20 border-b border-line">
        <div className="mx-auto flex max-w-[1760px] flex-wrap items-center gap-x-7 gap-y-3 px-4 py-3 sm:px-6">
          <button type="button" onClick={() => setPage(role.landing)} className="flex cursor-pointer items-center gap-2.5" aria-label="AEGIS home">
            <ShieldMark />
            <span className="font-mono font-bold tracking-[0.28em]">AEGIS</span>
          </button>

          <nav aria-label="Console sections" className="order-3 flex w-full gap-1 overflow-x-auto md:order-none md:w-auto md:flex-1">
            {PAGES.map((p) => {
              const on = p.id === page;
              return (
                <button
                  key={p.id}
                  type="button"
                  onClick={() => setPage(p.id)}
                  aria-current={on ? 'page' : undefined}
                  className={`h-11 shrink-0 cursor-pointer rounded-lg px-3.5 text-sm font-medium whitespace-nowrap transition-colors ${
                    on ? 'bg-signal-soft text-signal font-semibold' : 'text-soft hover:bg-panel-2 hover:text-fg'
                  }`}
                >
                  {p.label}
                  {p.id === 'governance' && (run?.summary?.pending_review ?? 0) > 0 && (
                    <span className="ml-2 rounded-full bg-warn px-1.5 font-mono text-[11px] font-bold text-on-warn">{run?.summary?.pending_review}</span>
                  )}
                </button>
              );
            })}
          </nav>

          <div className="ml-auto flex items-center gap-3">
            <span className={`hidden items-center gap-2 font-mono text-xs sm:flex ${apiError ? 'text-warn' : 'text-ok'}`}>
              <span className={`h-2 w-2 rounded-full ${apiError ? 'bg-warn' : 'bg-ok'}`} aria-hidden="true" />
              {apiError
                ? 'API OFFLINE'
                : control?.paused
                  ? 'PAUSED'
                  : health?.llm.configured
                    ? `${providerName(health.llm.provider).toUpperCase()} ONLINE`
                    : 'RULES MODE'}
            </span>
            <div className="flex h-10 w-10 items-center justify-center rounded-full border border-signal bg-panel-2 text-sm font-bold" title={`${operatorName} (${account.username}) · ${role.label}`}>
              {initialsOf(account.name)}
            </div>
            <ThemeToggle />
            <button type="button" onClick={signOut} aria-label="Sign out" title="Sign out" className="flex h-11 w-11 cursor-pointer items-center justify-center rounded-lg border border-line-strong text-soft hover:text-fg">
              <LogOut className="h-4 w-4" aria-hidden="true" />
            </button>
          </div>
        </div>
      </header>

      <main className="mx-auto flex w-full max-w-[1760px] flex-1 flex-col gap-7 px-4 pt-8 pb-16 sm:px-6">
        <section className="flex flex-wrap items-end justify-between gap-5">
          <div className="flex min-w-0 flex-[1_1_520px] flex-col gap-2">
            <Kicker className="text-signal">
              {greetingFor()}, {operatorName} · {role.label}
            </Kicker>
            <h1 className="m-0 text-[clamp(26px,3vw,38px)] leading-tight font-bold tracking-tight text-balance">
              Agentic AI for <span className="aegis-accent-text">Autonomous Threat Detection</span> and Response
            </h1>
            <p className="m-0 text-base text-soft">{role.focus}</p>
          </div>
          {runs.length > 0 && (
            <label className="flex min-w-0 flex-[0_1_360px] flex-col gap-2 font-mono text-xs uppercase tracking-[0.12em] text-muted">
              Run
              <select value={runId ?? ''} onChange={(e) => { setSelected(null); setRunId(e.target.value); }} className="h-11 rounded-lg border border-line-strong bg-panel px-3 font-sans text-sm normal-case tracking-normal text-fg">
                {runs.map((r) => (
                  <option key={r.id} value={r.id}>
                    {new Date(r.created_at).toLocaleString()} · {datasetLabel(r.config.dataset_id)} · {r.status.toLowerCase()} · {r.operator}
                  </option>
                ))}
              </select>
            </label>
          )}
        </section>

        {control?.paused && (
          <div role="alert" className="flex flex-wrap items-center gap-3 rounded-xl border border-crit-line bg-crit-soft p-4 text-sm text-crit">
            <OctagonPause className="h-5 w-5 flex-none" aria-hidden="true" />
            <span className="min-w-0 flex-1">
              <strong>AEGIS is paused.</strong> No run can start and running work stopped after its current window
              {control.by && ` · by ${control.by.replace('user:', '')}`}
              {control.at && ` at ${new Date(control.at).toLocaleString()}`}
              {control.reason && ` · “${control.reason}”`}
            </span>
            {can(account, 'control') && (
              <button type="button" onClick={() => void setPaused(false, '')} className="h-10 cursor-pointer rounded-lg border border-crit px-4 font-semibold hover:bg-crit/10">
                Resume
              </button>
            )}
          </div>
        )}

        {apiError && (
          <div role="alert" className="flex flex-wrap items-start gap-3 rounded-xl border border-warn-line bg-warn-soft p-4 text-sm text-warn">
            <AlertTriangle className="mt-0.5 h-4 w-4 flex-none" aria-hidden="true" />
            <span className="min-w-0 flex-1">{apiError}</span>
            <button type="button" onClick={() => void connect()} className="cursor-pointer font-semibold underline">
              Retry
            </button>
          </div>
        )}

        {runId && run?.id !== runId && page !== 'overview' ? (
          <SkeletonPage />
        ) : (
        <div key={page} className="aegis-page flex flex-col gap-7">
        {page === 'overview' && (
          <Overview run={run} account={account} paused={!!control?.paused} datasets={datasets} health={health} selected={selected} onStart={startRun} onInspect={inspect} />
        )}
        {page === 'incidents' && (
          <Incidents key={run?.id} run={run} role={account.role} canReview={can(account, 'review')} selected={selected} onSelect={setSelected} onReview={review} />
        )}
        {page === 'governance' && (
          <Governance run={run} control={control} canControl={can(account, 'control')} onPause={setPaused} onOpen={inspect} />
        )}
        {page === 'agents' && <Agents run={run} />}
        {page === 'walkthrough' && <Walkthrough run={run} />}
        </div>
        )}
      </main>

      <footer className="border-t border-line">
        <div className="mx-auto flex max-w-[1760px] flex-wrap justify-between gap-2.5 px-4 py-5 text-sm text-muted sm:px-6">
          <span>AEGIS · {PROJECT_TITLE}: {PROJECT_SUBTITLE}</span>
          <span className="font-mono">LangGraph · {providerName(health?.llm.provider)} · Backend server · CIC-IDS2018</span>
        </div>
      </footer>
    </div>
  );
}

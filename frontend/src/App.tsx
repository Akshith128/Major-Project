import { useEffect, useState } from 'react';
import { AlertTriangle, Download, LogOut } from 'lucide-react';
import type { AegisSystemSnapshot, DataSourceMode, MitigationProposalResult } from './types/aegis';
import { loadAegisSnapshot, requestThreatMitigation } from './services/aegisService';
import {
  PAGES,
  clearOperator,
  greetingFor,
  initialsOf,
  loadOperator,
  roleSpec,
  saveOperator,
  type ConsolePage,
  type OperatorProfile,
} from './lib/operator';
import { Onboarding } from './components/Onboarding';
import { CommandCenter } from './components/CommandCenter';
import { ThreatEvents } from './components/ThreatEvents';
import { AgentWorkflow } from './components/AgentWorkflow';
import { Evaluation } from './components/Evaluation';
import { RunResults } from './components/RunResults';
import { Kicker, ShieldMark } from './components/ui';

const PROJECT_TITLE = 'Agentic AI for Autonomous Threat Detection and Response';
const INTERRUPTED_RUN_ID = '51b07a510c424400a3e237b2a838c946';

export default function App() {
  const [operator, setOperator] = useState<OperatorProfile | null>(() => loadOperator());
  const [signedIn, setSignedIn] = useState(() => operator !== null);
  const [page, setPage] = useState<ConsolePage>(() =>
    operator ? roleSpec(operator.role).landing : 'overview'
  );
  const [dataSourceMode, setDataSourceMode] = useState<DataSourceMode>('demo_provider');
  const [snapshot, setSnapshot] = useState<AegisSystemSnapshot | null>(null);
  const [backendError, setBackendError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [selectedEventId, setSelectedEventId] = useState<string | null>(null);
  const [lastMitigation, setLastMitigation] = useState<MitigationProposalResult | null>(null);

  useEffect(() => {
    let mounted = true;
    setLoading(true);
    loadAegisSnapshot(dataSourceMode)
      .then((data) => {
        if (!mounted) return;
        setSnapshot(data);
        setBackendError(null);
      })
      .catch((err) => {
        if (!mounted) return;
        setBackendError(err instanceof Error ? err.message : 'Backend connection unavailable');
      })
      .finally(() => mounted && setLoading(false));
    return () => {
      mounted = false;
    };
  }, [dataSourceMode]);

  const enter = (profile: OperatorProfile) => {
    saveOperator(profile);
    setOperator(profile);
    setPage(roleSpec(profile.role).landing);
    setSignedIn(true);
  };

  const switchOperator = () => {
    if (!operator?.remember) clearOperator();
    setSignedIn(false);
  };

  const inspect = (id: string) => {
    setSelectedEventId(id);
    setPage('events');
  };

  const propose = async (eventId: string, action: string) => {
    setLastMitigation(await requestThreatMitigation(eventId, action, dataSourceMode));
  };

  const exportJson = () => {
    if (!snapshot) return;
    const blob = new Blob([JSON.stringify(snapshot, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `aegis_${snapshot.dataSourceMode}_snapshot.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  if (!signedIn || !operator) {
    return <Onboarding initial={operator} onEnter={enter} />;
  }

  const role = roleSpec(operator.role);
  const displayName = operator.name || 'Operator';
  const live = dataSourceMode === 'backend_adapter';

  return (
    <div className="flex min-h-screen flex-col">
      <header className="sticky top-0 z-20 border-b border-line bg-ink-raised/95 backdrop-blur">
        <div className="mx-auto flex max-w-[1320px] flex-wrap items-center gap-x-7 gap-y-3 px-4 py-3 sm:px-6">
          <button
            type="button"
            onClick={() => setPage(role.landing)}
            className="flex cursor-pointer items-center gap-2.5"
            aria-label="AEGIS home"
          >
            <ShieldMark />
            <span className="font-mono font-bold tracking-[0.28em]">AEGIS</span>
          </button>

          <nav aria-label="Console sections" className="order-3 flex w-full gap-1 overflow-x-auto lg:order-none lg:w-auto lg:flex-1">
            {PAGES.map((p) => {
              const on = p.id === page;
              return (
                <button
                  key={p.id}
                  type="button"
                  onClick={() => setPage(p.id)}
                  aria-current={on ? 'page' : undefined}
                  className={`h-11 shrink-0 cursor-pointer rounded-lg px-3.5 text-sm font-medium whitespace-nowrap ${
                    on ? 'bg-panel-2 text-white shadow-[inset_0_-2px_0_var(--color-signal)]' : 'text-soft hover:text-fg'
                  }`}
                >
                  {p.label}
                </button>
              );
            })}
          </nav>

          <div className="ml-auto flex items-center gap-3">
            <div className="flex rounded-lg border border-line-strong p-0.5" role="group" aria-label="Data source">
              {(
                [
                  ['demo_provider', 'Demo'],
                  ['backend_adapter', 'Live API'],
                ] as const
              ).map(([mode, label]) => (
                <button
                  key={mode}
                  type="button"
                  aria-pressed={dataSourceMode === mode}
                  onClick={() => setDataSourceMode(mode)}
                  className={`h-9 cursor-pointer rounded-md px-3 text-xs font-semibold ${
                    dataSourceMode === mode ? 'bg-panel-2 text-fg' : 'text-muted hover:text-fg'
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>
            <div
              className="flex h-10 w-10 items-center justify-center rounded-full border border-signal bg-panel-2 text-sm font-bold"
              title={`${displayName} · ${role.label}`}
            >
              {initialsOf(operator.name)}
            </div>
            <button
              type="button"
              onClick={switchOperator}
              aria-label="Switch operator"
              title="Switch operator"
              className="flex h-11 w-11 cursor-pointer items-center justify-center rounded-lg border border-line-strong text-soft hover:text-fg"
            >
              <LogOut className="h-4 w-4" aria-hidden="true" />
            </button>
          </div>
        </div>
      </header>

      <main className="mx-auto flex w-full max-w-[1320px] flex-1 flex-col gap-7 px-4 pt-8 pb-16 sm:px-6">
        <section className="flex flex-wrap items-end justify-between gap-5">
          <div className="flex min-w-0 flex-[1_1_520px] flex-col gap-2">
            <Kicker className="text-signal">
              {greetingFor()}, {displayName} · {role.label}
            </Kicker>
            <h1 className="m-0 text-[clamp(26px,3vw,36px)] leading-tight font-bold tracking-tight text-balance">
              {PROJECT_TITLE}
            </h1>
            <p className="m-0 text-base text-soft">{role.focus}</p>
          </div>
          <div className="flex flex-wrap items-center gap-2.5">
            <span
              className={`flex items-center gap-2 font-mono text-xs ${
                backendError ? 'text-warn' : live ? 'text-ok' : 'text-soft'
              }`}
            >
              <span
                className={`h-2 w-2 rounded-full ${backendError ? 'bg-warn' : live ? 'bg-ok' : 'bg-soft'}`}
                aria-hidden="true"
              />
              {backendError ? 'BACKEND UNAVAILABLE' : live ? 'LIVE FASTAPI' : 'DEMO DATA'}
              {loading ? ' · loading…' : ''}
            </span>
            <button
              type="button"
              onClick={exportJson}
              disabled={!snapshot}
              className="flex h-11 cursor-pointer items-center gap-2 rounded-lg border border-line-strong bg-panel px-4 text-sm font-medium hover:border-signal disabled:opacity-50"
            >
              <Download className="h-4 w-4" aria-hidden="true" /> Export telemetry JSON
            </button>
          </div>
        </section>

        {snapshot && (
          <p className="m-0 rounded-lg border border-line bg-panel px-4 py-3 font-mono text-xs text-soft">
            {snapshot.provenanceBanner}
          </p>
        )}

        {backendError && (
          <div role="alert" className="flex flex-wrap items-start gap-3 rounded-xl border border-[#6B4F1A] bg-[#3A2A0C] p-4 text-sm text-warn">
            <AlertTriangle className="mt-0.5 h-4 w-4 flex-none" aria-hidden="true" />
            <span className="min-w-0 flex-1">{backendError}</span>
            {live && (
              <button
                type="button"
                onClick={() => setDataSourceMode('demo_provider')}
                className="cursor-pointer font-semibold underline"
              >
                Return to demo data
              </button>
            )}
          </div>
        )}

        {page === 'runs' ? (
          <RunResults initialRunId={INTERRUPTED_RUN_ID} />
        ) : !snapshot ? (
          <p className="m-0 text-sm text-muted">{loading ? 'Loading telemetry…' : 'No telemetry loaded.'}</p>
        ) : page === 'overview' ? (
          <CommandCenter snapshot={snapshot} role={operator.role} onInspect={inspect} />
        ) : page === 'events' ? (
          <ThreatEvents
            snapshot={snapshot}
            selectedId={selectedEventId}
            onSelect={setSelectedEventId}
            lastMitigation={lastMitigation}
            onPropose={propose}
          />
        ) : page === 'workflow' ? (
          <AgentWorkflow nodes={snapshot.agentNodes} />
        ) : (
          <Evaluation matrices={snapshot.evaluationMatrices} sourceLabel={snapshot.backendStatusMessage} />
        )}
      </main>

      <footer className="border-t border-line">
        <div className="mx-auto flex max-w-[1320px] flex-wrap justify-between gap-2.5 px-4 py-5 text-sm text-muted sm:px-6">
          <span>AEGIS · {PROJECT_TITLE}: Enhancing Cybersecurity Governance and Digital Trust</span>
          <span className="font-mono">FastAPI · LangGraph · Gemini</span>
        </div>
      </footer>
    </div>
  );
}

import { useEffect, useState } from 'react';
import { ArrowRight } from 'lucide-react';
import type { Run } from '../api';
import { Kicker, Panel, Stat } from './ui';

const AGENTS = [
  {
    id: 'monitoring',
    name: 'Monitoring agent',
    kind: 'Deterministic',
    role: 'Scores every traffic window for homogeneity — attack traffic repeats one flow pattern — and gates which windows need reasoning.',
    output: 'score, suspicious, signals',
  },
  {
    id: 'detection',
    name: 'Detection agent',
    kind: 'Gemini · rule fallback',
    role: 'Reads the label-free traffic features and decides whether the window is malicious, which attack family it is and how confident it is.',
    output: 'threat, attack_type, confidence, reasoning',
  },
  {
    id: 'risk',
    name: 'Risk agent',
    kind: 'Deterministic',
    role: 'Combines detector confidence, monitoring score and attack impact, and escalates when the same attack repeats within the run.',
    output: 'risk score 0–100, severity, factors',
  },
  {
    id: 'response',
    name: 'Response agent',
    kind: 'Gemini · playbook fallback',
    role: 'Recommends concrete containment actions adapted to the traffic, starting from a standard playbook for the attack family.',
    output: 'actions, rationale (recommended, not executed)',
  },
  {
    id: 'governance',
    name: 'Governance agent',
    kind: 'Policy AEGIS-GOV-1',
    role: 'Applies the trust policy: auto-approves only low-impact, high-confidence responses; everything else waits for an analyst. Every decision is hash-chained into the audit trail.',
    output: 'NO_ACTION · AUTO_APPROVED · PENDING_REVIEW',
  },
];

export function Agents({ run }: { run: Run | null }) {
  const [traced, setTraced] = useState<number | null>(null);
  useEffect(() => setTraced(null), [run?.id]);

  const windows = run?.windows ?? [];
  const visits = (id: string) => windows.filter((w) => w.trace.includes(id)).length;
  const route = windows.find((w) => w.index === traced) ?? null;
  const detected = windows.filter((w) => w.detection);
  const threats = detected.filter((w) => w.detection?.threat);
  const viaGemini = detected.filter((w) => w.detection?.source === 'gemini').length;
  const severe = threats.filter((w) => w.risk?.severity === 'HIGH' || w.risk?.severity === 'CRITICAL').length;

  return (
    <div className="flex flex-col gap-5">
      <p className="m-0 max-w-3xl text-soft">
        Each traffic window runs through a LangGraph state machine. Clean windows exit after monitoring; suspicious ones go to the
        detection agent; confirmed threats are scored, given a response plan and passed to governance.
      </p>

      {run && windows.length > 0 && (
        <Panel title="Workflow for this run" meta={route ? `W${route.index}: ${route.trace.join(' → ')}` : 'pick a window to trace its route'}>
          <div className="flex flex-col gap-5">
            <ol className="m-0 flex list-none flex-wrap items-stretch gap-2.5 p-0" aria-label="Agent pipeline">
              {AGENTS.map((a, i) => {
                const lit = !route || route.trace.includes(a.id);
                return (
                  <li key={a.id} className="flex min-w-0 flex-[1_1_170px] items-center gap-2.5">
                    <div
                      className={`flex min-w-0 flex-1 flex-col gap-1 rounded-lg border p-3.5 transition-opacity ${
                        route ? (lit ? 'border-signal bg-[#122631]' : 'border-dashed border-line-strong opacity-40') : 'border-line-strong bg-ink-raised'
                      }`}
                    >
                      <span className="font-mono text-[11px] tracking-[0.14em] text-signal">{i + 1} · {a.name.replace(' agent', '').toUpperCase()}</span>
                      <span className="font-mono text-2xl font-bold">{visits(a.id)}</span>
                      <span className="text-xs text-muted">windows processed</span>
                    </div>
                    {i < AGENTS.length - 1 && <ArrowRight className="h-4 w-4 flex-none text-muted" aria-hidden="true" />}
                  </li>
                );
              })}
            </ol>
            <div className="flex flex-wrap items-center gap-2" role="group" aria-label="Trace a window">
              <span className="mr-1.5 text-sm text-soft">Highlight a window's route:</span>
              {windows.map((w) => {
                const on = traced === w.index;
                return (
                  <button
                    key={w.index}
                    type="button"
                    aria-pressed={on}
                    onClick={() => setTraced(on ? null : w.index)}
                    className={`h-9 min-w-11 cursor-pointer rounded-lg border px-2.5 font-mono text-xs font-semibold ${
                      on ? 'border-signal bg-signal text-signal-ink' : w.detection?.threat ? 'border-[#6B2A30] bg-[#3A1418] text-crit' : 'border-line-strong bg-ink-raised text-soft hover:text-fg'
                    }`}
                  >
                    W{w.index}
                  </button>
                );
              })}
            </div>
          </div>
        </Panel>
      )}

      {run && windows.length > 0 && (
        <section aria-label="Routing" className="grid grid-cols-1 gap-3.5 sm:grid-cols-2 xl:grid-cols-4">
          <Stat label="Clean → governance" value={windows.length - detected.length} note="Below the monitoring gate" tone="text-signal" />
          <Stat label="Cleared by detection" value={detected.length - threats.length} note={`${viaGemini} Gemini · ${detected.length - viaGemini} rules`} tone="text-warn" />
          <Stat label="Full pipeline" value={threats.length} note="Risk + response + governance" tone="text-crit" />
          <Stat label="High / critical" value={severe} note={`${threats.length - severe} medium or low`} />
        </section>
      )}

      <ol className="m-0 grid list-none grid-cols-1 gap-4 p-0 lg:grid-cols-2">
        {AGENTS.map((a, i) => (
          <li key={a.id} className="flex min-w-0 flex-col gap-3 rounded-xl border border-line bg-panel p-5">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <Kicker className="text-signal">
                Step {i + 1} · {a.kind}
              </Kicker>
              {run && (
                <span className="font-mono text-xs text-muted">
                  {visits(a.id)}/{run.windows.length} windows in this run
                </span>
              )}
            </div>
            <h3 className="m-0 text-lg font-semibold">{a.name}</h3>
            <p className="m-0 text-sm text-soft">{a.role}</p>
            <p className="m-0 font-mono text-xs text-muted">→ {a.output}</p>
          </li>
        ))}
      </ol>
    </div>
  );
}

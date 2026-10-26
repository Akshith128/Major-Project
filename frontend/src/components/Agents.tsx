import type { Run } from '../api';
import { Kicker } from './ui';

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
  const visits = (id: string) => run?.windows.filter((w) => w.trace.includes(id)).length;
  return (
    <div className="flex flex-col gap-5">
      <p className="m-0 max-w-3xl text-soft">
        Each traffic window runs through a LangGraph state machine. Clean windows exit after monitoring; suspicious ones go to the
        detection agent; confirmed threats are scored, given a response plan and passed to governance.
      </p>
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

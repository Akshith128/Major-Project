import type { AgentNodeSpec } from '../types/aegis';
import { Kicker } from './ui';

function ContractList({ label, items }: { label: string; items: string[] }) {
  return (
    <div className="flex flex-col gap-1.5">
      <Kicker>{label}</Kicker>
      <ul className="m-0 flex list-none flex-wrap gap-1.5 p-0">
        {items.map((i) => (
          <li key={i} className="rounded-md border border-line-strong bg-ink px-2 py-1 font-mono text-xs text-soft">
            {i}
          </li>
        ))}
      </ul>
    </div>
  );
}

export function AgentWorkflow({ nodes }: { nodes: AgentNodeSpec[] }) {
  return (
    <ol className="m-0 grid list-none grid-cols-1 gap-4 p-0 lg:grid-cols-2">
      {nodes.map((n) => (
        <li key={n.id} className="flex min-w-0 flex-col gap-4 rounded-xl border border-line bg-panel p-5">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <Kicker className="text-signal">
              Step {n.stepNumber} · {n.executionMode}
            </Kicker>
            <span className="font-mono text-xs text-muted">
              {n.invocationsInSlice}/{n.totalWindowsInSlice} windows
              {n.sampleLatencyMs !== null ? ` · ~${n.sampleLatencyMs} ms` : ''}
            </span>
          </div>
          <div className="flex flex-col gap-1.5">
            <h3 className="m-0 text-lg font-semibold">{n.name}</h3>
            <p className="m-0 text-sm text-soft">{n.role}</p>
          </div>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <ContractList label="Input" items={n.inputContract} />
            <ContractList label="Output" items={n.outputContract} />
          </div>
          <div className="flex flex-col gap-2 border-t border-line pt-3 text-sm">
            <p className="m-0 text-soft">
              <span className="font-semibold text-fg">Isolation · </span>
              {n.isolationGuarantee}
            </p>
            <p className="m-0 text-soft">
              <span className="font-semibold text-fg">Fallback · </span>
              {n.fallbackBehavior}
            </p>
          </div>
        </li>
      ))}
    </ol>
  );
}

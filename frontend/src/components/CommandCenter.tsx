import type { AegisSystemSnapshot, NetworkWindowEvent, SeverityLevel } from '../types/aegis';
import type { OperatorRole } from '../lib/operator';
import { Panel, SeverityBadge, Stat, Verdict, formatRatio } from './ui';

const SEVERITY_RANK: Record<SeverityLevel, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  NOMINAL: 0,
};

export function bySeverity(a: NetworkWindowEvent, b: NetworkWindowEvent): number {
  return (
    SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
    b.monitoringSuspicionScore - a.monitoringSuspicionScore
  );
}

function SuspicionChart({
  events,
  onInspect,
}: {
  events: NetworkWindowEvent[];
  onInspect: (id: string) => void;
}) {
  return (
    <Panel title="Monitoring suspicion by window" meta="score 0–1 · click a bar to inspect">
      <div className="flex h-48 items-end gap-3 overflow-x-auto pb-1" role="list">
        {events.map((ev) => {
          const pct = Math.max(4, Math.min(100, ev.monitoringSuspicionScore * 100));
          const attack = ev.overallPipelinePrediction === 'ATTACK';
          return (
            <button
              key={ev.id}
              type="button"
              role="listitem"
              onClick={() => onInspect(ev.id)}
              aria-label={`Window ${ev.windowIndex}: suspicion ${ev.monitoringSuspicionScore.toFixed(2)}, verdict ${ev.overallPipelinePrediction ?? 'none'}`}
              className="group flex h-full min-w-11 flex-1 cursor-pointer flex-col items-center justify-end gap-2"
            >
              <span className="font-mono text-xs text-soft">{ev.monitoringSuspicionScore.toFixed(2)}</span>
              <span
                className={`w-full max-w-16 rounded-t-md transition-[filter] group-hover:brightness-125 ${
                  attack ? 'bg-crit' : 'bg-signal/60'
                }`}
                style={{ height: `${pct}%` }}
              />
              <span className="font-mono text-xs text-muted">W{ev.windowIndex}</span>
            </button>
          );
        })}
      </div>
      <div className="mt-3 flex flex-wrap gap-4 text-xs text-muted">
        <span className="flex items-center gap-2">
          <span className="h-2.5 w-2.5 rounded-sm bg-crit" /> Pipeline verdict ATTACK
        </span>
        <span className="flex items-center gap-2">
          <span className="h-2.5 w-2.5 rounded-sm bg-signal/60" /> BENIGN or no verdict
        </span>
      </div>
    </Panel>
  );
}

function ForYou({
  role,
  snapshot,
  onInspect,
}: {
  role: OperatorRole;
  snapshot: AegisSystemSnapshot;
  onInspect: (id: string) => void;
}) {
  const overall = snapshot.evaluationMatrices.find((m) => /overall/i.test(m.layerName));
  const detector = snapshot.evaluationMatrices.find((m) => /detector/i.test(m.layerName));

  if (role === 'manager' || role === 'researcher') {
    const m = role === 'manager' ? overall : detector;
    return (
      <Panel title={role === 'manager' ? 'Digital trust at a glance' : 'Detector performance'} meta="for you">
        {m ? (
          <div className="flex flex-col gap-4">
            <p className="m-0 text-sm text-soft">{m.description}</p>
            <dl className="m-0 grid grid-cols-2 gap-3">
              {(
                [
                  ['Precision', m.precision],
                  ['Recall', m.recall],
                  ['F1', m.f1],
                  ['False-positive rate', m.fpr],
                ] as const
              ).map(([k, v]) => (
                <div key={k} className="rounded-lg border border-line bg-ink-raised px-3 py-2.5">
                  <dt className="font-mono text-[11px] uppercase tracking-wider text-muted">{k}</dt>
                  <dd className="m-0 mt-1 font-mono text-xl font-bold text-signal">{formatRatio(v)}</dd>
                </div>
              ))}
            </dl>
            {role === 'manager' && (
              <p className="m-0 text-sm text-soft">
                No response is reported as successful without a backend confirmation receipt.
              </p>
            )}
          </div>
        ) : (
          <p className="m-0 text-sm text-muted">No evaluation metrics in this snapshot.</p>
        )}
      </Panel>
    );
  }

  const items =
    role === 'responder'
      ? snapshot.events.filter(
          (e) => e.overallPipelinePrediction === 'ATTACK' && e.responseStatus !== 'CONFIRMED_BY_BACKEND'
        )
      : [...snapshot.events].sort(bySeverity).slice(0, 3);

  return (
    <Panel
      title={role === 'responder' ? 'Awaiting containment confirmation' : 'Top of your queue'}
      meta="for you"
      bodyClassName="p-2"
    >
      {items.length === 0 ? (
        <p className="m-0 p-3 text-sm text-muted">Nothing waiting. The pipeline is quiet.</p>
      ) : (
        <ul className="m-0 flex list-none flex-col p-0">
          {items.map((ev) => (
            <li key={ev.id}>
              <button
                type="button"
                onClick={() => onInspect(ev.id)}
                className="flex w-full cursor-pointer items-center justify-between gap-3 rounded-lg px-3 py-3 text-left hover:bg-panel-2"
              >
                <span className="flex min-w-0 flex-col gap-0.5">
                  <span className="font-mono text-sm">{ev.id}</span>
                  <span className="truncate text-xs text-muted">{ev.proposedMitigationAction}</span>
                </span>
                <SeverityBadge severity={ev.severity} />
              </button>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

export function CommandCenter({
  snapshot,
  role,
  onInspect,
}: {
  snapshot: AegisSystemSnapshot;
  role: OperatorRole;
  onInspect: (id: string) => void;
}) {
  const ev = snapshot.events;
  const invoked = ev.filter((e) => e.detectorInvoked).length;
  const parsed = ev.filter((e) => e.detectorStatus === 'PARSED').length;
  const attacks = ev.filter((e) => e.overallPipelinePrediction === 'ATTACK').length;
  const confirmed = ev.filter((e) => e.responseStatus === 'CONFIRMED_BY_BACKEND').length;
  const flows = ev.reduce((t, e) => t + e.flowCount, 0);

  return (
    <div className="flex flex-col gap-6">
      <section aria-label="Key indicators" className="grid grid-cols-1 gap-3.5 sm:grid-cols-2 xl:grid-cols-4">
        <Stat label="Windows analysed" value={ev.length} note={`${flows} flows · batch ${snapshot.batchSize}`} />
        <Stat label="Attack windows" value={attacks} note="Overall pipeline verdict" tone="text-crit" />
        <Stat label="Detector parsed" value={`${parsed}/${invoked}`} note="LLM outputs parsed / invoked" tone="text-signal" />
        <Stat
          label="Responses confirmed"
          value={confirmed}
          note={snapshot.backendConnected ? 'Backend receipts received' : 'Backend not connected'}
          tone="text-ok"
        />
      </section>

      <div className="flex flex-wrap gap-5">
        <div className="min-w-0 flex-[999_1_560px]">
          <SuspicionChart events={ev} onInspect={onInspect} />
        </div>
        <div className="min-w-0 flex-[1_1_320px]">
          <ForYou role={role} snapshot={snapshot} onInspect={onInspect} />
        </div>
      </div>

      <div className="flex flex-wrap gap-5">
        <Panel
          title="Threat events"
          meta={`${snapshot.activeDataset} · slice ${snapshot.sliceRange}`}
          className="flex-[999_1_560px]"
          bodyClassName="overflow-x-auto"
        >
          <table className="w-full min-w-[640px] border-collapse text-sm">
            <thead>
              <tr className="text-left font-mono text-[11px] uppercase tracking-wider text-muted">
                <th className="px-5 py-3 font-medium">Window</th>
                <th className="px-2 py-3 font-medium">Source → Service</th>
                <th className="px-2 py-3 font-medium">Verdict</th>
                <th className="px-2 py-3 font-medium">Severity</th>
                <th className="px-5 py-3 font-medium">
                  <span className="sr-only">Inspect</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {[...ev].sort(bySeverity).map((e) => (
                <tr key={e.id} className="border-t border-line">
                  <td className="px-5 py-3.5 font-mono text-soft">{e.id}</td>
                  <td className="px-2 py-3.5">
                    {e.sourceSubnet} → {e.destinationService}
                  </td>
                  <td className="px-2 py-3.5">
                    <Verdict value={e.overallPipelinePrediction} />
                  </td>
                  <td className="px-2 py-3.5">
                    <SeverityBadge severity={e.severity} />
                  </td>
                  <td className="px-5 py-2 text-right">
                    <button
                      type="button"
                      onClick={() => onInspect(e.id)}
                      className="h-9 cursor-pointer rounded-md border border-line-strong px-3 text-sm text-soft hover:border-signal hover:text-fg"
                    >
                      Inspect
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>

        <Panel title="Agent pipeline" className="flex-[1_1_300px]">
          <ol className="m-0 flex list-none flex-col gap-1 p-0">
            {snapshot.agentNodes.map((n) => (
              <li key={n.id} className="flex items-start gap-3 py-2">
                <span className="flex h-7 w-7 flex-none items-center justify-center rounded-md border border-line-strong font-mono text-xs text-signal">
                  {n.stepNumber}
                </span>
                <span className="flex min-w-0 flex-col gap-0.5">
                  <span className="text-sm font-semibold">{n.name}</span>
                  <span className="font-mono text-[11px] uppercase tracking-wider text-muted">{n.executionMode}</span>
                </span>
              </li>
            ))}
          </ol>
        </Panel>
      </div>
    </div>
  );
}

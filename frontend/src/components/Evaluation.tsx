import { useMemo, useState } from 'react';
import { CheckCircle2, XCircle } from 'lucide-react';
import type { ConfusionMatrixSummary } from '../types/aegis';
import {
  TARGET_DATASET,
  VALIDATION_SCENARIOS,
  replayRecordedDetectorOutputs,
  type ConfusionMetrics,
} from '../data/stageCData';
import { Kicker, Panel, formatRatio } from './ui';

function MetricGrid({
  tp,
  tn,
  fp,
  fn,
  precision,
  recall,
  f1,
  fpr,
}: {
  tp: number;
  tn: number;
  fp: number;
  fn: number;
  precision: number | null;
  recall: number | null;
  f1: number | null;
  fpr: number | null;
}) {
  return (
    <div className="flex flex-col gap-3">
      <div className="grid grid-cols-2 gap-2" aria-label="Confusion matrix">
        {(
          [
            ['TP', tp, 'text-ok'],
            ['FP', fp, 'text-warn'],
            ['FN', fn, 'text-crit'],
            ['TN', tn, 'text-soft'],
          ] as const
        ).map(([k, v, tone]) => (
          <div key={k} className="rounded-lg border border-line bg-ink-raised px-3 py-2">
            <span className="font-mono text-[11px] text-muted">{k}</span>
            <span className={`block font-mono text-xl font-bold ${tone}`}>{v}</span>
          </div>
        ))}
      </div>
      <dl className="m-0 grid grid-cols-4 gap-2 text-center">
        {(
          [
            ['Prec', precision],
            ['Recall', recall],
            ['F1', f1],
            ['FPR', fpr],
          ] as const
        ).map(([k, v]) => (
          <div key={k}>
            <dt className="font-mono text-[11px] uppercase text-muted">{k}</dt>
            <dd className="m-0 font-mono text-sm text-signal">{formatRatio(v)}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

function fromStageC(m: ConfusionMetrics) {
  return {
    tp: m.tp,
    tn: m.tn,
    fp: m.fp,
    fn: m.fn,
    precision: m.precision,
    recall: m.recall,
    f1: m.f1,
    fpr: m.false_positive_rate,
  };
}

function StageCReplay() {
  const [scenarioId, setScenarioId] = useState(VALIDATION_SCENARIOS[0].id);
  const scenario = VALIDATION_SCENARIOS.find((s) => s.id === scenarioId) ?? VALIDATION_SCENARIOS[0];
  const result = useMemo(
    () => replayRecordedDetectorOutputs(scenario.records, scenario.expectedProvenance, TARGET_DATASET),
    [scenario]
  );

  return (
    <Panel title="Stage C offline replay harness" meta={TARGET_DATASET}>
      <div className="flex flex-col gap-5">
        <div className="flex flex-col gap-2">
          <label htmlFor="stagec-scenario" className="font-mono text-xs uppercase tracking-[0.12em] text-muted">
            Validation scenario
          </label>
          <select
            id="stagec-scenario"
            value={scenarioId}
            onChange={(e) => setScenarioId(e.target.value)}
            className="h-11 cursor-pointer rounded-lg border border-line-strong bg-ink px-3 text-sm text-fg"
          >
            {VALIDATION_SCENARIOS.map((s) => (
              <option key={s.id} value={s.id}>
                {s.title}
              </option>
            ))}
          </select>
          <p className="m-0 text-sm text-soft">{scenario.description}</p>
        </div>

        {result.ok ? (
          <div className="flex flex-col gap-4">
            <p className="m-0 flex items-center gap-2 text-sm text-ok" role="status">
              <CheckCircle2 className="h-4 w-4" aria-hidden="true" /> Replay accepted · no label leakage, provenance verified
            </p>
            <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
              {(
                [
                  ['Monitoring', result.artifact.metrics.monitoring],
                  ['Detector', result.artifact.metrics.detector],
                  ['Overall pipeline', result.artifact.metrics.overall_pipeline],
                ] as const
              ).map(([label, m]) => (
                <div key={label} className="flex flex-col gap-3 rounded-lg border border-line p-4">
                  <Kicker className="text-fg">{label}</Kicker>
                  <MetricGrid {...fromStageC(m)} />
                </div>
              ))}
            </div>
          </div>
        ) : (
          <div className="flex flex-col gap-2" role="status">
            <p className="m-0 flex items-center gap-2 text-sm text-crit">
              <XCircle className="h-4 w-4" aria-hidden="true" /> Replay rejected — {result.errors.length} validation
              failure{result.errors.length === 1 ? '' : 's'}
            </p>
            <ul className="m-0 flex list-none flex-col gap-1.5 p-0">
              {result.errors.map((err, i) => (
                <li key={i} className="rounded-lg border border-line bg-ink-raised px-3 py-2 text-sm">
                  <span className="font-mono text-xs text-warn">{err.code}</span>
                  <span className="block text-soft">{err.message}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </Panel>
  );
}

export function Evaluation({
  matrices,
  sourceLabel,
}: {
  matrices: ConfusionMatrixSummary[];
  sourceLabel: string;
}) {
  return (
    <div className="flex flex-col gap-5">
      <section className="grid grid-cols-1 gap-4 md:grid-cols-3" aria-label="Digital trust guarantees">
        {[
          ['Confirmed responses only', 'A mitigation is never reported as successful without a backend confirmation receipt.'],
          ['Ground truth isolated', 'Labels are stripped before monitoring and detector nodes; they are used for evaluation only.'],
          ['Provenance on every run', 'Each snapshot is tagged synthetic, recorded, demo or backend report for audit.'],
        ].map(([t, d]) => (
          <div key={t} className="flex flex-col gap-2 rounded-xl border border-line bg-panel p-5">
            <h3 className="m-0 text-base font-semibold">{t}</h3>
            <p className="m-0 text-sm text-soft">{d}</p>
          </div>
        ))}
      </section>

      <Panel title="Layer evaluation" meta={sourceLabel}>
        <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
          {matrices.map((m) => (
            <div key={m.layerName} className="flex flex-col gap-3 rounded-lg border border-line p-4">
              <div className="flex flex-col gap-1">
                <Kicker className="text-fg">{m.layerName}</Kicker>
                <span className="text-xs text-muted">
                  {m.eligiblePredictions}/{m.population} eligible · {m.excludedWindows} excluded
                </span>
              </div>
              <MetricGrid {...m} />
            </div>
          ))}
        </div>
      </Panel>

      <StageCReplay />
    </div>
  );
}

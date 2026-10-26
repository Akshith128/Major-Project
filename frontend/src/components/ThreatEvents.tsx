import { useMemo, useState } from 'react';
import { RefreshCw, Search, ShieldAlert } from 'lucide-react';
import type {
  AegisSystemSnapshot,
  DetectorParseStatus,
  MitigationProposalResult,
  NetworkWindowEvent,
  PredictionClass,
  SeverityLevel,
} from '../types/aegis';
import { Kicker, Panel, SeverityBadge, Verdict } from './ui';

type FallbackFilter = 'ALL' | 'FALLBACK_ONLY' | 'PRIMARY_ONLY';

const selectClass =
  'h-11 cursor-pointer rounded-lg border border-line-strong bg-ink px-3 text-sm text-fg';

function EventDetail({
  event,
  lastMitigation,
  onPropose,
}: {
  event: NetworkWindowEvent;
  lastMitigation: MitigationProposalResult | null;
  onPropose: (eventId: string, action: string) => Promise<void>;
}) {
  const [busy, setBusy] = useState(false);
  const attempt = lastMitigation?.eventId === event.id ? lastMitigation : null;
  const f = event.featureSnapshot;
  const features: [string, string][] = [
    ['Fwd packets/s', f.fwdPacketsPerSec.toFixed(1)],
    ['Bwd packets/s', f.bwdPacketsPerSec.toFixed(1)],
    ['SYN flag ratio', f.synFlagRatio.toFixed(3)],
    ['RST flag ratio', f.rstFlagRatio.toFixed(3)],
    ['Flow duration (ms)', f.flowDurationMeanMs.toFixed(1)],
    ['Payload bytes', f.payloadBytesMean.toFixed(0)],
  ];

  const propose = async () => {
    setBusy(true);
    try {
      await onPropose(event.id, event.proposedMitigationAction);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Panel title={`Window ${event.windowIndex} · ${event.id}`} meta={`rows [${event.rowStart}, ${event.rowEnd})`}>
      <div className="flex flex-col gap-5">
        <div className="flex flex-wrap items-center gap-3">
          <SeverityBadge severity={event.severity} />
          <Verdict value={event.overallPipelinePrediction} />
          <span className="font-mono text-xs text-muted">
            detector {event.detectorStatus}
            {event.usedMonitoringFallback ? ' · monitoring fallback' : ''}
          </span>
        </div>

        <div className="flex flex-col gap-1.5">
          <Kicker>Monitoring trigger</Kicker>
          <p className="m-0 text-sm text-soft">{event.monitoringTriggerReason}</p>
        </div>

        <dl className="m-0 grid grid-cols-2 gap-2.5 sm:grid-cols-3">
          {features.map(([k, v]) => (
            <div key={k} className="rounded-lg border border-line bg-ink-raised px-3 py-2">
              <dt className="text-xs text-muted">{k}</dt>
              <dd className="m-0 mt-0.5 font-mono text-base">{v}</dd>
            </div>
          ))}
        </dl>

        <div className="flex flex-col gap-1.5">
          <Kicker>Raw detector output</Kicker>
          <pre className="m-0 max-h-48 overflow-auto rounded-lg border border-line bg-ink p-3 text-xs whitespace-pre-wrap text-soft">
            {event.detectorRawOutput ?? 'Detector not invoked for this window.'}
          </pre>
        </div>

        <div className="flex flex-col gap-3 rounded-lg border border-line-strong bg-ink-raised p-4">
          <div className="flex items-start gap-2.5">
            <ShieldAlert className="mt-0.5 h-4 w-4 flex-none text-warn" aria-hidden="true" />
            <div className="flex flex-col gap-1">
              <span className="text-sm font-semibold">Proposed response</span>
              <span className="text-sm text-soft">{event.proposedMitigationAction}</span>
              <span className="font-mono text-xs text-muted">status {event.responseStatus}</span>
            </div>
          </div>
          <button
            type="button"
            onClick={propose}
            disabled={busy || event.responseStatus === 'NO_ACTION_REQUIRED'}
            className="h-11 cursor-pointer self-start rounded-lg bg-signal px-4 text-sm font-bold text-signal-ink disabled:cursor-not-allowed disabled:opacity-50"
          >
            {busy ? 'Submitting…' : 'Submit mitigation proposal'}
          </button>
          {attempt && (
            <p
              role="status"
              className={`m-0 text-sm ${attempt.confirmedByBackend ? 'text-ok' : 'text-warn'}`}
            >
              {attempt.message}
            </p>
          )}
        </div>
      </div>
    </Panel>
  );
}

export function ThreatEvents({
  snapshot,
  selectedId,
  onSelect,
  lastMitigation,
  onPropose,
}: {
  snapshot: AegisSystemSnapshot;
  selectedId: string | null;
  onSelect: (id: string) => void;
  lastMitigation: MitigationProposalResult | null;
  onPropose: (eventId: string, action: string) => Promise<void>;
}) {
  const [query, setQuery] = useState('');
  const [decision, setDecision] = useState<'ALL' | PredictionClass>('ALL');
  const [detector, setDetector] = useState<'ALL' | DetectorParseStatus>('ALL');
  const [severity, setSeverity] = useState<'ALL' | SeverityLevel>('ALL');
  const [fallback, setFallback] = useState<FallbackFilter>('ALL');

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return snapshot.events.filter((ev) => {
      if (severity !== 'ALL' && ev.severity !== severity) return false;
      if (decision !== 'ALL' && ev.overallPipelinePrediction !== decision) return false;
      if (detector !== 'ALL' && ev.detectorStatus !== detector) return false;
      if (fallback === 'FALLBACK_ONLY' && !ev.usedMonitoringFallback) return false;
      if (fallback === 'PRIMARY_ONLY' && ev.usedMonitoringFallback) return false;
      if (q) {
        const hay = `${ev.id} ${ev.protocolSummary} ${ev.sourceSubnet} ${ev.destinationService} ${ev.monitoringTriggerReason} ${ev.detectorStatus}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [snapshot, query, decision, detector, severity, fallback]);

  const selected =
    snapshot.events.find((e) => e.id === selectedId) ?? filtered[0] ?? snapshot.events[0] ?? null;

  const reset = () => {
    setQuery('');
    setDecision('ALL');
    setDetector('ALL');
    setSeverity('ALL');
    setFallback('ALL');
  };

  return (
    <div className="flex flex-col gap-5">
      <Panel
        title="Threat event explorer"
        meta={`${filtered.length}/${snapshot.events.length} windows shown`}
      >
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-[2fr_repeat(4,minmax(0,1fr))_auto]">
          <label className="relative">
            <span className="sr-only">Search windows</span>
            <Search className="absolute top-1/2 left-3 h-4 w-4 -translate-y-1/2 text-muted" aria-hidden="true" />
            <input
              type="search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search subnet, service, window…"
              className="h-11 w-full rounded-lg border border-line-strong bg-ink pr-3 pl-9 text-sm text-fg placeholder:text-muted"
            />
          </label>
          <select aria-label="Filter by pipeline decision" value={decision} onChange={(e) => setDecision(e.target.value as 'ALL' | PredictionClass)} className={selectClass}>
            <option value="ALL">All decisions</option>
            <option value="ATTACK">ATTACK</option>
            <option value="BENIGN">BENIGN</option>
          </select>
          <select aria-label="Filter by detector status" value={detector} onChange={(e) => setDetector(e.target.value as 'ALL' | DetectorParseStatus)} className={selectClass}>
            <option value="ALL">All detector statuses</option>
            <option value="PARSED">PARSED</option>
            <option value="UNPARSEABLE">UNPARSEABLE</option>
            <option value="NOT_INVOKED">NOT_INVOKED</option>
            <option value="MISSING">MISSING</option>
          </select>
          <select aria-label="Filter by severity" value={severity} onChange={(e) => setSeverity(e.target.value as 'ALL' | SeverityLevel)} className={selectClass}>
            <option value="ALL">All severities</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
            <option value="NOMINAL">NOMINAL</option>
          </select>
          <select aria-label="Filter by fallback usage" value={fallback} onChange={(e) => setFallback(e.target.value as FallbackFilter)} className={selectClass}>
            <option value="ALL">All routing</option>
            <option value="FALLBACK_ONLY">Monitoring fallback</option>
            <option value="PRIMARY_ONLY">Detector primary</option>
          </select>
          <button
            type="button"
            onClick={reset}
            className="flex h-11 cursor-pointer items-center justify-center gap-2 rounded-lg border border-line-strong px-3 text-sm text-soft hover:text-fg"
          >
            <RefreshCw className="h-4 w-4" aria-hidden="true" /> Reset
          </button>
        </div>
      </Panel>

      <div className="flex flex-wrap gap-5">
        <Panel className="flex-[999_1_520px]" bodyClassName="overflow-x-auto">
          {filtered.length === 0 ? (
            <p className="m-0 p-5 text-sm text-muted">No windows match these filters.</p>
          ) : (
            <table className="w-full min-w-[680px] border-collapse text-sm">
              <thead>
                <tr className="text-left font-mono text-[11px] uppercase tracking-wider text-muted">
                  <th className="px-5 py-3 font-medium">Window</th>
                  <th className="px-2 py-3 text-right font-medium">Flows</th>
                  <th className="px-2 py-3 text-right font-medium">Suspicion</th>
                  <th className="px-2 py-3 font-medium">Detector</th>
                  <th className="px-2 py-3 font-medium">Verdict</th>
                  <th className="px-5 py-3 font-medium">Severity</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((ev) => {
                  const on = selected?.id === ev.id;
                  return (
                    <tr key={ev.id} className={`border-t border-line ${on ? 'bg-[#122631]' : ''}`}>
                      <td className="px-5 py-2">
                        <button
                          type="button"
                          onClick={() => onSelect(ev.id)}
                          aria-current={on}
                          className="cursor-pointer py-1.5 text-left font-mono text-signal hover:underline"
                        >
                          {ev.id}
                        </button>
                      </td>
                      <td className="px-2 py-2 text-right font-mono">{ev.flowCount}</td>
                      <td className="px-2 py-2 text-right font-mono">{ev.monitoringSuspicionScore.toFixed(2)}</td>
                      <td className="px-2 py-2 font-mono text-xs text-soft">{ev.detectorStatus}</td>
                      <td className="px-2 py-2">
                        <Verdict value={ev.overallPipelinePrediction} />
                      </td>
                      <td className="px-5 py-2">
                        <SeverityBadge severity={ev.severity} />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </Panel>
        {selected && (
          <div className="min-w-0 flex-[1_1_380px]">
            <EventDetail event={selected} lastMitigation={lastMitigation} onPropose={onPropose} />
          </div>
        )}
      </div>
    </div>
  );
}

import {
  AegisSystemSnapshot,
  DataSourceMode,
  MitigationProposalResult,
  NetworkWindowEvent,
  TimeSeriesTrafficPoint,
} from '../types/aegis';
import { getDemoSystemSnapshot } from '../data/demoDataProvider';

/**
 * AEGIS ISOLATED SERVICE LAYER (`aegisService.ts`)
 * ---------------------------------------------------------------------------
 * This service module isolates all data retrieval and action dispatch behind
 * an explicit adapter interface.
 *
 * - No backend API paths are invented or hardcoded.
 * - No Gemini API keys or secrets are referenced or exposed in browser code.
 * - No threat mitigation action ever reports success unless a real backend
 *   adapter explicitly confirms it with a cryptographic/transactional receipt.
 *
 * HOW TO CONNECT YOUR EXISTING PYTHON / FASTAPI / LANGGRAPH BACKEND LATER:
 * Register a custom `AegisBackendAdapter` via `registerBackendAdapter()` that
 * maps your existing backend routes to `fetchSystemSnapshot` and
 * `submitMitigationProposal`.
 */

export interface AegisBackendAdapter {
  fetchSystemSnapshot: () => Promise<AegisSystemSnapshot>;
  submitMitigationProposal: (
    eventId: string,
    proposedAction: string
  ) => Promise<MitigationProposalResult>;
}

let registeredAdapter: AegisBackendAdapter | null = null;

type BackendMetric = Record<string, number | null>;
type BackendRow = Record<string, unknown>;
type BackendReport = {
  dataset: string;
  pilot_start_row: number;
  pilot_end_row: number;
  pilot_batch_size: number;
  run_status: string;
  run_final_decision_code: string | null;
  rows: BackendRow[];
  monitoring_metrics: BackendMetric;
  llm_metrics: BackendMetric;
  pipeline_metrics: BackendMetric;
};

export type StoredRunRow = {
  window: number;
  window_status: string;
  ground_truth_dominant_label: string | null;
  ground_truth_binary_class: 'ATTACK' | 'BENIGN' | null;
  label_counts: Record<string, number>;
  monitoring_anomaly_prediction: 'ATTACK' | 'BENIGN' | null;
  llm_detection_prediction: 'ATTACK' | 'BENIGN' | null;
  llm_detection_invoked: boolean;
  overall_pipeline_prediction: 'ATTACK' | 'BENIGN' | null;
  enforced_severity: string | null;
  risk_score: number | null;
  verification_outcome: string | null;
};

export type StoredRunResult = {
  run_id: string;
  status: string;
  result: {
    run_status: string;
    dataset: string;
    pilot_start_row: number;
    pilot_end_row: number;
    pilot_batch_size: number;
    pilot_selection: string;
    interruption_reason: string | null;
    run_final_decision_code: string | null;
    monitoring_window_count: number;
    completed_window_count: number;
    partial_window_count: number;
    incomplete_window_count: number;
    rows: StoredRunRow[];
  } | null;
  error?: string | null;
};

const BACKEND_URL =
  import.meta.env.VITE_AEGIS_API_BASE_URL || 'http://127.0.0.1:8000';

async function backendRequest<T>(
  path: string,
  init?: RequestInit
): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${BACKEND_URL}${path}`, init);
  } catch (error) {
    throw new Error(
      `FastAPI backend is unavailable at ${BACKEND_URL}. ${
        error instanceof Error ? error.message : ''
      }`.trim()
    );
  }

  let payload: unknown = {};
  try {
    payload = await response.json();
  } catch {
    // The status code below still gives the caller a useful failure.
  }

  if (!response.ok) {
    const detail =
      typeof payload === 'object' &&
      payload !== null &&
      'detail' in payload &&
      typeof payload.detail === 'string'
        ? payload.detail
        : `HTTP ${response.status}`;
    throw new Error(`FastAPI request failed: ${detail}`);
  }
  return payload as T;
}

function prediction(value: unknown): 'ATTACK' | 'BENIGN' | null {
  return value === 'ATTACK' || value === 'BENIGN' ? value : null;
}

function numberValue(value: unknown, fallback = 0): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback;
}

function metric(
  layerName: string,
  description: string,
  values: BackendMetric,
  population: number,
  provenance: 'backend_report'
) {
  return {
    layerName,
    description,
    provenance,
    population,
    eligiblePredictions: numberValue(
      values.evaluated_rows ?? values.detector_invocations
    ),
    excludedWindows: numberValue(values.missing_predictions),
    tp: numberValue(values.TP),
    tn: numberValue(values.TN),
    fp: numberValue(values.FP),
    fn: numberValue(values.FN),
    accuracy: values.accuracy ?? null,
    precision: values.precision ?? null,
    recall: values.recall ?? null,
    f1: values.f1 ?? null,
    fpr: values.false_positive_rate ?? null,
  };
}

function reportToSnapshot(report: BackendReport): AegisSystemSnapshot {
  const events: NetworkWindowEvent[] = report.rows.map((row, index) => {
    const window = numberValue(row.window, index + 1);
    const rowStart = report.pilot_start_row + index * report.pilot_batch_size;
    const rowEnd = Math.min(
      report.pilot_end_row,
      rowStart + report.pilot_batch_size
    );
    const groundTruth = prediction(row.ground_truth_binary_class);
    const monitoringPrediction = prediction(
      row.monitoring_anomaly_prediction
    );
    const detectorPrediction = prediction(row.llm_detection_prediction);
    const overallPrediction = prediction(row.overall_pipeline_prediction);
    const labelCounts =
      typeof row.label_counts === 'object' &&
      row.label_counts !== null
        ? (row.label_counts as Record<string, unknown>)
        : {};
    const attackFlows = Object.entries(labelCounts).reduce(
      (total, [label, count]) =>
        label.toLowerCase() === 'benign'
          ? total
          : total + numberValue(count),
      0
    );
    const benignFlows = numberValue(labelCounts.Benign);
    const detectorInvoked = row.llm_detection_invoked === true;
    const rawOutput =
      typeof row.raw_detection_response === 'string'
        ? row.raw_detection_response
        : null;
    const detectorStatus = !detectorInvoked
      ? 'NOT_INVOKED'
      : detectorPrediction
        ? 'PARSED'
        : rawOutput
          ? 'UNPARSEABLE'
          : 'MISSING';
    const severity =
      row.enforced_severity === 'CRITICAL' ||
      row.enforced_severity === 'HIGH' ||
      row.enforced_severity === 'MEDIUM' ||
      row.enforced_severity === 'LOW'
        ? row.enforced_severity
        : 'NOMINAL';

    return {
      id: `BACKEND-WIN-${window}`,
      dataset: report.dataset,
      windowIndex: window,
      rowStart,
      rowEnd,
      flowCount: rowEnd - rowStart,
      timestamp: 'Not provided by backend',
      protocolSummary: 'Not provided by backend',
      sourceSubnet: 'Not provided by backend',
      destinationService: 'Not provided by backend',
      monitoringDecision: monitoringPrediction || 'BENIGN',
      monitoringSuspicionScore: numberValue(row.risk_score) / 100,
      monitoringTriggerReason: 'Mapped from the FastAPI evaluation report.',
      detectorInvoked,
      detectorStatus,
      detectorRawOutput: rawOutput,
      detectorParsedPrediction: detectorPrediction,
      overallPipelinePrediction: overallPrediction,
      usedMonitoringFallback: overallPrediction === null,
      severity,
      provenance: 'backend_report',
      sourceLabel: 'FastAPI evaluator report',
      evaluationOnlyGroundTruth: groundTruth || 'BENIGN',
      evaluationOnlyAttackFlows: attackFlows,
      evaluationOnlyBenignFlows: benignFlows,
      proposedMitigationAction:
        'No mitigation endpoint exists in the current FastAPI contract.',
      responseStatus: 'UNCONFIRMED_BACKEND_ACTION_UNAVAILABLE',
      backendConfirmationReceipt: null,
      featureSnapshot: {
        fwdPacketsPerSec: 0,
        bwdPacketsPerSec: 0,
        synFlagRatio: 0,
        rstFlagRatio: 0,
        flowDurationMeanMs: 0,
        payloadBytesMean: 0,
      },
    };
  });

  const timeSeries: TimeSeriesTrafficPoint[] = events.map((event) => ({
    windowLabel: `W${event.windowIndex}`,
    rowRange: `[${event.rowStart}, ${event.rowEnd})`,
    totalFlows: event.flowCount,
    suspicionScore: event.monitoringSuspicionScore,
    attackFlowsEvalOnly: event.evaluationOnlyAttackFlows,
    benignFlowsEvalOnly: event.evaluationOnlyBenignFlows,
    detectorInvoked: event.detectorInvoked,
    detectorStatus: event.detectorStatus,
    overallDecision: event.overallPipelinePrediction,
  }));
  const population = events.length;

  return {
    dataSourceMode: 'backend_adapter',
    backendConnected: true,
    backendStatusMessage: 'Connected to the existing FastAPI evaluator API.',
    activeDataset: report.dataset,
    sliceRange: `[${report.pilot_start_row}, ${report.pilot_end_row})`,
    batchSize: report.pilot_batch_size,
    provenanceBanner:
      'FASTAPI BACKEND REPORT · provenance is reported as backend data only; no confirmed mitigation action is claimed.',
    events,
    timeSeries,
    agentNodes: getDemoSystemSnapshot().agentNodes,
    evaluationMatrices: [
      metric(
        'Monitoring predictions',
        'Monitoring predictions returned by the FastAPI evaluator.',
        report.monitoring_metrics,
        population,
        'backend_report'
      ),
      metric(
        'Detector-only predictions',
        'Parsed detector predictions returned by the FastAPI evaluator.',
        report.llm_metrics,
        population,
        'backend_report'
      ),
      metric(
        'Overall pipeline predictions',
        'Overall predictions and documented monitoring fallbacks returned by the FastAPI evaluator.',
        report.pipeline_metrics,
        population,
        'backend_report'
      ),
    ],
  };
}

export function createFastApiAdapter(): AegisBackendAdapter {
  return {
    async fetchSystemSnapshot() {
      await backendRequest<{ status: string }>('/api/v1/health');
      const datasets = await backendRequest<{
        datasets: Array<{ dataset_id: string }>;
      }>('/api/v1/datasets');
      const dataset = datasets.datasets[0];
      if (!dataset?.dataset_id) {
        throw new Error('FastAPI returned no datasets.');
      }
      await backendRequest(
        `/api/v1/datasets/${encodeURIComponent(dataset.dataset_id)}/schema`
      );

      const response = await backendRequest<{
        run_id: string;
        status: string;
      }>('/api/v1/runs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          dataset_id: dataset.dataset_id,
          start_row: 0,
          end_row: 800,
          batch_size: 100,
          max_graph_executions: 1,
        }),
      });
      const result = await backendRequest<{
        result?: BackendReport;
        error?: string;
      }>(`/api/v1/runs/${encodeURIComponent(response.run_id)}/result`);
      if (!result.result) {
        throw new Error(result.error || 'FastAPI returned no run report.');
      }
      return reportToSnapshot(result.result);
    },
    async submitMitigationProposal(eventId, proposedAction) {
      return {
        eventId,
        proposedAction,
        confirmedByBackend: false,
        status: 'UNCONFIRMED_BACKEND_ACTION_UNAVAILABLE',
        message:
          'Backend connected, but no mitigation endpoint exists in the current FastAPI contract; proposal was not executed.',
        timestamp: new Date().toISOString(),
      };
    },
  };
}

export function registerBackendAdapter(adapter: AegisBackendAdapter): void {
  registeredAdapter = adapter;
}

export function isBackendAdapterRegistered(): boolean {
  return registeredAdapter !== null;
}

export async function loadStoredRunResult(
  runId: string
): Promise<StoredRunResult> {
  const normalizedRunId = runId.trim();
  if (!normalizedRunId) {
    throw new Error('Enter a run ID to load its stored result.');
  }
  return backendRequest<StoredRunResult>(
    `/api/v1/runs/${encodeURIComponent(normalizedRunId)}/result`
  );
}

export async function loadAegisSnapshot(
  preferredMode: DataSourceMode = 'demo_provider'
): Promise<AegisSystemSnapshot> {
  if (preferredMode === 'backend_adapter') {
    if (!registeredAdapter) {
      throw new Error(
        'Backend adapter is not connected. Register your existing FastAPI/LangGraph adapter in src/services/aegisService.ts before switching to Live Backend mode.'
      );
    }
    return registeredAdapter.fetchSystemSnapshot();
  }

  // Return isolated demo data snapshot
  return getDemoSystemSnapshot();
}

export async function requestThreatMitigation(
  eventId: string,
  proposedAction: string,
  activeMode: DataSourceMode
): Promise<MitigationProposalResult> {
  if (activeMode === 'backend_adapter' && registeredAdapter) {
    const backendResult = await registeredAdapter.submitMitigationProposal(
      eventId,
      proposedAction
    );
    return backendResult;
  }

  // Strict guarantee: Never claim a threat response succeeded when the backend
  // has not confirmed it.
  return {
    eventId,
    proposedAction,
    confirmedByBackend: false,
    status: 'UNCONFIRMED_BACKEND_DISCONNECTED',
    message:
      'Mitigation Not Confirmed: Demo Data Provider active. Threat response is strictly logged as an unexecuted proposal.',
    timestamp: new Date().toISOString(),
  };
}

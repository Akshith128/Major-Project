export type ProvenanceType = 'genuine_recorded' | 'synthetic_test';

export type DetectorStatus = 'PARSED' | 'UNPARSEABLE' | 'MISSING' | 'NOT_INVOKED';

export type PredictionLabel = 'ATTACK' | 'BENIGN';

export interface RecordedDetectorRecord {
  dataset: string;
  window: number;
  row_start: number;
  row_end: number;
  detector_invoked: boolean;
  raw_output: string | null;
  parsed_prediction: string | null;
  source: string;
  provenance: string;
  invocation_reason?: string;
  // Potential illegal/leakage fields tested in validation:
  ground_truth?: unknown;
  label_counts?: unknown;
  dominant_label?: unknown;
  binary_truth?: unknown;
  derived_from_ground_truth?: boolean;
  mock_configuration_id?: string;
}

export interface ProductionWindowSpec {
  window: number;
  row_start: number;
  row_end: number;
  row_count: number;
  monitoring_decision: PredictionLabel;
  monitoring_suspicion_score: number;
  evaluation_only_truth: PredictionLabel;
  evaluation_only_attack_rows: number;
  evaluation_only_benign_rows: number;
}

export interface EvaluatedWindowResult {
  window: number;
  row_start: number;
  row_end: number;
  row_count: number;
  detector_invoked: boolean;
  detector_status: DetectorStatus;
  raw_output: string | null;
  parsed_prediction: PredictionLabel | null;
  monitoring_prediction: PredictionLabel;
  overall_prediction: PredictionLabel;
  used_monitoring_fallback: boolean;
  source: string;
  provenance: ProvenanceType;
  invocation_reason: string;
  evaluation_truth: PredictionLabel;
  detector_outcome: 'TP' | 'TN' | 'FP' | 'FN' | 'EXCLUDED';
  overall_outcome: 'TP' | 'TN' | 'FP' | 'FN';
}

export interface ConfusionMetrics {
  tp: number;
  tn: number;
  fp: number;
  fn: number;
  accuracy: number | null;
  precision: number | null;
  recall: number | null;
  f1: number | null;
  false_positive_rate: number | null;
  population: number;
  eligible_predictions: number;
  evaluated_rows: number;
  missing_predictions: number;
  excluded_rows: number;
}

export interface PredictionAvailability {
  total_windows: number;
  detector_invocations: number;
  detector_predictions: number;
  unparseable_outputs: number;
  missing_or_not_invoked_outputs: number;
  overall_predictions: number;
  monitoring_fallbacks: number;
}

export interface StageCReplayArtifact {
  schema_version: string;
  stage: 'Stage C';
  evaluation_configuration: {
    dataset_name: string;
    start_row: number;
    end_row: number;
    batch_size: number;
    expected_provenance: ProvenanceType;
    recorded_output_provenance: ProvenanceType;
    recorded_output_sources: string[];
    labels_exposed_to_detector: false;
  };
  prediction_availability: PredictionAvailability;
  metrics: {
    detector: ConfusionMetrics;
    monitoring: ConfusionMetrics;
    overall_pipeline: ConfusionMetrics;
  };
  windows: EvaluatedWindowResult[];
}

export interface ValidationFailure {
  code:
    | 'DUPLICATE_WINDOW_IDENTITY'
    | 'MISSING_WINDOW_RECORD'
    | 'UNKNOWN_WINDOW_IDENTITY'
    | 'DATASET_MISMATCH'
    | 'RANGE_MISMATCH'
    | 'UNSUPPORTED_PROVENANCE'
    | 'PROVENANCE_EXPECTATION_MISMATCH'
    | 'INVALID_PREDICTION_VALUE'
    | 'NON_INVOKED_WITH_OUTPUT'
    | 'LABEL_LEAKAGE_DETECTED'
    | 'GROUND_TRUTH_DERIVED_REJECTED'
    | 'STAGE_B_MOCK_REJECTED';
  message: string;
  window?: number;
  field?: string;
}

export const TARGET_DATASET = 'Botnet-Friday-02-03-2018_TrafficForML_CICFlowMeter.parquet';
export const SLICE_START_ROW = 1000;
export const SLICE_END_ROW = 1405;
export const BATCH_SIZE = 100;

export const PRODUCTION_WINDOWS: ProductionWindowSpec[] = [
  {
    window: 1,
    row_start: 1000,
    row_end: 1100,
    row_count: 100,
    monitoring_decision: 'BENIGN',
    monitoring_suspicion_score: 0.14,
    evaluation_only_truth: 'BENIGN',
    evaluation_only_attack_rows: 0,
    evaluation_only_benign_rows: 100,
  },
  {
    window: 2,
    row_start: 1100,
    row_end: 1200,
    row_count: 100,
    monitoring_decision: 'ATTACK',
    monitoring_suspicion_score: 0.82,
    evaluation_only_truth: 'ATTACK',
    evaluation_only_attack_rows: 94,
    evaluation_only_benign_rows: 6,
  },
  {
    window: 3,
    row_start: 1200,
    row_end: 1300,
    row_count: 100,
    monitoring_decision: 'ATTACK',
    monitoring_suspicion_score: 0.79,
    evaluation_only_truth: 'ATTACK',
    evaluation_only_attack_rows: 88,
    evaluation_only_benign_rows: 12,
  },
  {
    window: 4,
    row_start: 1300,
    row_end: 1400,
    row_count: 100,
    monitoring_decision: 'ATTACK',
    monitoring_suspicion_score: 0.91,
    evaluation_only_truth: 'ATTACK',
    evaluation_only_attack_rows: 100,
    evaluation_only_benign_rows: 0,
  },
  {
    window: 5,
    row_start: 1400,
    row_end: 1405,
    row_count: 5,
    monitoring_decision: 'BENIGN',
    monitoring_suspicion_score: 0.08,
    evaluation_only_truth: 'BENIGN',
    evaluation_only_attack_rows: 0,
    evaluation_only_benign_rows: 5,
  },
];

export const STAGE_C_SYNTHETIC_FIXTURE: RecordedDetectorRecord[] = [
  {
    dataset: TARGET_DATASET,
    window: 1,
    row_start: 1000,
    row_end: 1100,
    detector_invoked: false,
    raw_output: null,
    parsed_prediction: null,
    source: 'offline-test-fixture',
    provenance: 'synthetic_test',
    invocation_reason: 'synthetic_record',
  },
  {
    dataset: TARGET_DATASET,
    window: 2,
    row_start: 1100,
    row_end: 1200,
    detector_invoked: true,
    raw_output: 'recorded attack',
    parsed_prediction: 'ATTACK',
    source: 'offline-test-fixture',
    provenance: 'synthetic_test',
    invocation_reason: 'synthetic_record',
  },
  {
    dataset: TARGET_DATASET,
    window: 3,
    row_start: 1200,
    row_end: 1300,
    detector_invoked: true,
    raw_output: 'unparseable',
    parsed_prediction: null,
    source: 'offline-test-fixture',
    provenance: 'synthetic_test',
    invocation_reason: 'synthetic_record',
  },
  {
    dataset: TARGET_DATASET,
    window: 4,
    row_start: 1300,
    row_end: 1400,
    detector_invoked: true,
    raw_output: 'recorded attack',
    parsed_prediction: 'ATTACK',
    source: 'offline-test-fixture',
    provenance: 'synthetic_test',
    invocation_reason: 'synthetic_record',
  },
  {
    dataset: TARGET_DATASET,
    window: 5,
    row_start: 1400,
    row_end: 1405,
    detector_invoked: false,
    raw_output: null,
    parsed_prediction: null,
    source: 'offline-test-fixture',
    provenance: 'synthetic_test',
    invocation_reason: 'synthetic_record',
  },
];

const FORBIDDEN_LABEL_KEYS = new Set([
  'ground_truth',
  'label',
  'labels',
  'label_counts',
  'dominant_label',
  'binary_truth',
  'attack_rows',
  'benign_rows',
  'evaluation_truth',
]);

function computeMetricsForPredictions(
  items: Array<{ prediction: PredictionLabel | null; truth: PredictionLabel }>,
  totalPopulation: number
): ConfusionMetrics {
  let tp = 0;
  let tn = 0;
  let fp = 0;
  let fn = 0;
  let eligible = 0;

  for (const item of items) {
    if (item.prediction === null) {
      continue;
    }
    eligible += 1;
    if (item.prediction === 'ATTACK' && item.truth === 'ATTACK') tp += 1;
    else if (item.prediction === 'BENIGN' && item.truth === 'BENIGN') tn += 1;
    else if (item.prediction === 'ATTACK' && item.truth === 'BENIGN') fp += 1;
    else if (item.prediction === 'BENIGN' && item.truth === 'ATTACK') fn += 1;
  }

  const missing = totalPopulation - eligible;
  const accuracy = eligible > 0 ? (tp + tn) / eligible : null;
  const precision = tp + fp > 0 ? tp / (tp + fp) : null;
  const recall = tp + fn > 0 ? tp / (tp + fn) : null;
  const f1 =
    precision !== null && recall !== null && precision + recall > 0
      ? (2 * precision * recall) / (precision + recall)
      : null;
  const falsePositiveRate = fp + tn > 0 ? fp / (fp + tn) : 0.0;

  return {
    tp,
    tn,
    fp,
    fn,
    accuracy,
    precision,
    recall,
    f1,
    false_positive_rate: eligible > 0 ? falsePositiveRate : null,
    population: totalPopulation,
    eligible_predictions: eligible,
    evaluated_rows: eligible,
    missing_predictions: missing,
    excluded_rows: missing,
  };
}

export function replayRecordedDetectorOutputs(
  records: RecordedDetectorRecord[],
  expectedProvenance: ProvenanceType = 'synthetic_test',
  datasetName: string = TARGET_DATASET
): { ok: true; artifact: StageCReplayArtifact } | { ok: false; errors: ValidationFailure[] } {
  const errors: ValidationFailure[] = [];

  const expectedMap = new Map<string, ProductionWindowSpec>();
  for (const w of PRODUCTION_WINDOWS) {
    expectedMap.set(`${w.window}:${w.row_start}:${w.row_end}`, w);
  }

  const seenIdentities = new Set<string>();
  const seenWindowNumbers = new Set<number>();
  const matchedRecords = new Map<number, RecordedDetectorRecord>();

  for (const rec of records) {
    // 1. Check Stage B mock artifact contamination
    if (rec.mock_configuration_id) {
      errors.push({
        code: 'STAGE_B_MOCK_REJECTED',
        message: `Record for window ${rec.window} contains mock_configuration_id="${rec.mock_configuration_id}". Stage B deterministic feature mocks are not recorded detector outputs.`,
        window: rec.window,
        field: 'mock_configuration_id',
      });
    }

    // 2. Check ground-truth derivation flag
    if (rec.derived_from_ground_truth === true) {
      errors.push({
        code: 'GROUND_TRUTH_DERIVED_REJECTED',
        message: `Record for window ${rec.window} is flagged as derived_from_ground_truth. Label-derived records are strictly prohibited.`,
        window: rec.window,
        field: 'derived_from_ground_truth',
      });
    }

    // 3. Check forbidden label leakage keys
    for (const key of Object.keys(rec)) {
      const value = rec[key as keyof RecordedDetectorRecord];
      if (FORBIDDEN_LABEL_KEYS.has(key) && value !== undefined) {
        errors.push({
          code: 'LABEL_LEAKAGE_DETECTED',
          message: `Record for window ${rec.window} contains forbidden ground-truth field "${key}". Detector interface must stay strictly isolated from labels.`,
          window: rec.window,
          field: key,
        });
      }
    }

    // 4. Dataset filename validation
    if (rec.dataset !== datasetName) {
      errors.push({
        code: 'DATASET_MISMATCH',
        message: `Window ${rec.window} dataset "${rec.dataset}" does not match expected dataset "${datasetName}".`,
        window: rec.window,
        field: 'dataset',
      });
    }

    // 5. Provenance validation
    if (rec.provenance !== 'genuine_recorded' && rec.provenance !== 'synthetic_test') {
      errors.push({
        code: 'UNSUPPORTED_PROVENANCE',
        message: `Window ${rec.window} has unsupported provenance "${rec.provenance}". Allowed values: genuine_recorded, synthetic_test.`,
        window: rec.window,
        field: 'provenance',
      });
    } else if (rec.provenance !== expectedProvenance) {
      errors.push({
        code: 'PROVENANCE_EXPECTATION_MISMATCH',
        message: `Window ${rec.window} provenance "${rec.provenance}" does not match expected harness mode "${expectedProvenance}".`,
        window: rec.window,
        field: 'provenance',
      });
    }

    // 6. Identity & Range validation
    const identityKey = `${rec.window}:${rec.row_start}:${rec.row_end}`;
    if (seenIdentities.has(identityKey) || seenWindowNumbers.has(rec.window)) {
      errors.push({
        code: 'DUPLICATE_WINDOW_IDENTITY',
        message: `Duplicate record detected for window ${rec.window} (${rec.row_start}, ${rec.row_end}).`,
        window: rec.window,
      });
    }
    seenIdentities.add(identityKey);
    seenWindowNumbers.add(rec.window);

    const specByWindowNum = PRODUCTION_WINDOWS.find((w) => w.window === rec.window);
    if (!specByWindowNum) {
      errors.push({
        code: 'UNKNOWN_WINDOW_IDENTITY',
        message: `Window ${rec.window} is not part of slice [${SLICE_START_ROW}, ${SLICE_END_ROW}).`,
        window: rec.window,
      });
    } else if (specByWindowNum.row_start !== rec.row_start || specByWindowNum.row_end !== rec.row_end) {
      errors.push({
        code: 'RANGE_MISMATCH',
        message: `Window ${rec.window} range [${rec.row_start}, ${rec.row_end}) does not match expected production slice [${specByWindowNum.row_start}, ${specByWindowNum.row_end}).`,
        window: rec.window,
      });
    }

    // 7. Prediction value validation
    if (
      rec.parsed_prediction !== null &&
      rec.parsed_prediction !== 'ATTACK' &&
      rec.parsed_prediction !== 'BENIGN'
    ) {
      errors.push({
        code: 'INVALID_PREDICTION_VALUE',
        message: `Window ${rec.window} has invalid parsed_prediction "${rec.parsed_prediction}". Only 'ATTACK', 'BENIGN', or null are permitted.`,
        window: rec.window,
        field: 'parsed_prediction',
      });
    }

    // 8. Non-invoked consistency check
    if (!rec.detector_invoked && (rec.raw_output !== null || rec.parsed_prediction !== null)) {
      errors.push({
        code: 'NON_INVOKED_WITH_OUTPUT',
        message: `Window ${rec.window} has detector_invoked=false but supplies non-null raw_output or parsed_prediction.`,
        window: rec.window,
      });
    }

    matchedRecords.set(rec.window, rec);
  }

  // 9. Check for missing windows
  for (const spec of PRODUCTION_WINDOWS) {
    if (!matchedRecords.has(spec.window)) {
      errors.push({
        code: 'MISSING_WINDOW_RECORD',
        message: `Missing recorded detector output for Window ${spec.window} [${spec.row_start}, ${spec.row_end}).`,
        window: spec.window,
      });
    }
  }

  if (errors.length > 0) {
    return { ok: false, errors };
  }

  const evaluatedWindows: EvaluatedWindowResult[] = [];
  let detectorInvocations = 0;
  let detectorPredictions = 0;
  let unparseableOutputs = 0;
  let missingOrNotInvokedOutputs = 0;
  let monitoringFallbacks = 0;
  const sourcesSet = new Set<string>();

  for (const spec of PRODUCTION_WINDOWS) {
    const rec = matchedRecords.get(spec.window)!;
    sourcesSet.add(rec.source);

    let status: DetectorStatus;
    const parsedPred = rec.parsed_prediction as PredictionLabel | null;

    if (!rec.detector_invoked) {
      status = 'NOT_INVOKED';
      missingOrNotInvokedOutputs += 1;
    } else {
      detectorInvocations += 1;
      if (parsedPred !== null) {
        status = 'PARSED';
        detectorPredictions += 1;
      } else if (rec.raw_output !== null && rec.raw_output.trim().length > 0) {
        status = 'UNPARSEABLE';
        unparseableOutputs += 1;
        missingOrNotInvokedOutputs += 1;
      } else {
        status = 'MISSING';
        missingOrNotInvokedOutputs += 1;
      }
    }

    const usedFallback = parsedPred === null;
    if (usedFallback) {
      monitoringFallbacks += 1;
    }

    const overallPred: PredictionLabel = parsedPred !== null ? parsedPred : spec.monitoring_decision;

    let detectorOutcome: 'TP' | 'TN' | 'FP' | 'FN' | 'EXCLUDED' = 'EXCLUDED';
    if (parsedPred !== null) {
      if (parsedPred === 'ATTACK' && spec.evaluation_only_truth === 'ATTACK') detectorOutcome = 'TP';
      else if (parsedPred === 'BENIGN' && spec.evaluation_only_truth === 'BENIGN') detectorOutcome = 'TN';
      else if (parsedPred === 'ATTACK' && spec.evaluation_only_truth === 'BENIGN') detectorOutcome = 'FP';
      else detectorOutcome = 'FN';
    }

    let overallOutcome: 'TP' | 'TN' | 'FP' | 'FN';
    if (overallPred === 'ATTACK' && spec.evaluation_only_truth === 'ATTACK') overallOutcome = 'TP';
    else if (overallPred === 'BENIGN' && spec.evaluation_only_truth === 'BENIGN') overallOutcome = 'TN';
    else if (overallPred === 'ATTACK' && spec.evaluation_only_truth === 'BENIGN') overallOutcome = 'FP';
    else overallOutcome = 'FN';

    evaluatedWindows.push({
      window: spec.window,
      row_start: spec.row_start,
      row_end: spec.row_end,
      row_count: spec.row_count,
      detector_invoked: rec.detector_invoked,
      detector_status: status,
      raw_output: rec.raw_output,
      parsed_prediction: parsedPred,
      monitoring_prediction: spec.monitoring_decision,
      overall_prediction: overallPred,
      used_monitoring_fallback: usedFallback,
      source: rec.source,
      provenance: rec.provenance as ProvenanceType,
      invocation_reason: rec.invocation_reason || 'recorded_replay',
      evaluation_truth: spec.evaluation_only_truth,
      detector_outcome: detectorOutcome,
      overall_outcome: overallOutcome,
    });
  }

  const totalWindows = PRODUCTION_WINDOWS.length;

  const detectorMetrics = computeMetricsForPredictions(
    evaluatedWindows.map((w) => ({ prediction: w.parsed_prediction, truth: w.evaluation_truth })),
    totalWindows
  );

  const monitoringMetrics = computeMetricsForPredictions(
    evaluatedWindows.map((w) => ({ prediction: w.monitoring_prediction, truth: w.evaluation_truth })),
    totalWindows
  );

  const overallMetrics = computeMetricsForPredictions(
    evaluatedWindows.map((w) => ({ prediction: w.overall_prediction, truth: w.evaluation_truth })),
    totalWindows
  );

  const artifact: StageCReplayArtifact = {
    schema_version: 'stage-c-recorded-replay-v1',
    stage: 'Stage C',
    evaluation_configuration: {
      dataset_name: datasetName,
      start_row: SLICE_START_ROW,
      end_row: SLICE_END_ROW,
      batch_size: BATCH_SIZE,
      expected_provenance: expectedProvenance,
      recorded_output_provenance: expectedProvenance,
      recorded_output_sources: Array.from(sourcesSet),
      labels_exposed_to_detector: false,
    },
    prediction_availability: {
      total_windows: totalWindows,
      detector_invocations: detectorInvocations,
      detector_predictions: detectorPredictions,
      unparseable_outputs: unparseableOutputs,
      missing_or_not_invoked_outputs: missingOrNotInvokedOutputs,
      overall_predictions: totalWindows,
      monitoring_fallbacks: monitoringFallbacks,
    },
    metrics: {
      detector: detectorMetrics,
      monitoring: monitoringMetrics,
      overall_pipeline: overallMetrics,
    },
    windows: evaluatedWindows,
  };

  return { ok: true, artifact };
}

export interface PresetValidationScenario {
  id: string;
  title: string;
  category: string;
  description: string;
  expectedProvenance: ProvenanceType;
  records: RecordedDetectorRecord[];
}

export const VALIDATION_SCENARIOS: PresetValidationScenario[] = [
  {
    id: 'valid_synthetic_stage_c',
    title: '01. Valid Synthetic Stage C Fixture (Baseline)',
    category: 'Nominal Replay',
    description:
      'Canonical 5-window synthetic fixture on [1000, 1405). Distinguishes NOT_INVOKED (W1, W5), PARSED (W2, W4), and UNPARSEABLE (W3) with monitoring fallbacks.',
    expectedProvenance: 'synthetic_test',
    records: STAGE_C_SYNTHETIC_FIXTURE,
  },
  {
    id: 'reject_stage_b_mock',
    title: '02. Reject Stage B Mock Artifact (deterministic-feature-v1)',
    category: 'Provenance Guard',
    description:
      'Attempts to pass the prior Stage B synthetic replay containing mock_configuration_id="deterministic-feature-v1" as recorded detector output.',
    expectedProvenance: 'genuine_recorded',
    records: STAGE_C_SYNTHETIC_FIXTURE.map((r) => ({
      ...r,
      provenance: 'genuine_recorded',
      mock_configuration_id: 'deterministic-feature-v1',
    })),
  },
  {
    id: 'reject_label_leakage',
    title: '03. Reject Ground-Truth Label Leakage in Record',
    category: 'Isolation Guard',
    description:
      'Injects dominant_label and label_counts into Window 2 record. Stage C enforces strict zero-label exposure to the detector interface.',
    expectedProvenance: 'synthetic_test',
    records: STAGE_C_SYNTHETIC_FIXTURE.map((r) =>
      r.window === 2
        ? {
            ...r,
            dominant_label: 'Bot',
            label_counts: { Bot: 94, Benign: 6 },
          }
        : r
    ),
  },
  {
    id: 'reject_ground_truth_derived',
    title: '04. Reject Ground-Truth-Derived Output Flag',
    category: 'Isolation Guard',
    description:
      'Flags Window 3 record with derived_from_ground_truth=true. Prevents circular evaluation where predictions are synthesized from labels.',
    expectedProvenance: 'synthetic_test',
    records: STAGE_C_SYNTHETIC_FIXTURE.map((r) =>
      r.window === 3 ? { ...r, derived_from_ground_truth: true } : r
    ),
  },
  {
    id: 'reject_non_invoked_with_output',
    title: '05. Reject Non-Invoked Window Carrying Prediction',
    category: 'Consistency Guard',
    description:
      'Window 1 has detector_invoked=false but supplies parsed_prediction="BENIGN". Non-invoked windows must not smuggle predictions.',
    expectedProvenance: 'synthetic_test',
    records: STAGE_C_SYNTHETIC_FIXTURE.map((r) =>
      r.window === 1
        ? { ...r, detector_invoked: false, parsed_prediction: 'BENIGN', raw_output: 'benign' }
        : r
    ),
  },
  {
    id: 'reject_range_mismatch',
    title: '06. Reject Row-Range Identity Mismatch',
    category: 'Identity Guard',
    description:
      'Alters Window 4 row_end from 1400 to 1395. Records must match the exact (window, row_start, row_end) tuple.',
    expectedProvenance: 'synthetic_test',
    records: STAGE_C_SYNTHETIC_FIXTURE.map((r) =>
      r.window === 4 ? { ...r, row_end: 1395 } : r
    ),
  },
  {
    id: 'reject_duplicate_window',
    title: '07. Reject Duplicate Window Identity',
    category: 'Identity Guard',
    description:
      'Supplies two competing detector records for Window 2 [1100, 1200) and omits Window 5.',
    expectedProvenance: 'synthetic_test',
    records: [
      STAGE_C_SYNTHETIC_FIXTURE[0],
      STAGE_C_SYNTHETIC_FIXTURE[1],
      STAGE_C_SYNTHETIC_FIXTURE[1],
      STAGE_C_SYNTHETIC_FIXTURE[2],
      STAGE_C_SYNTHETIC_FIXTURE[3],
    ],
  },
  {
    id: 'reject_unsupported_provenance',
    title: '08. Reject Ambiguous / Unverified Provenance Tag',
    category: 'Provenance Guard',
    description:
      'Supplies provenance="unverified_capture" on Window 2. Only explicit genuine_recorded or synthetic_test values are accepted.',
    expectedProvenance: 'synthetic_test',
    records: STAGE_C_SYNTHETIC_FIXTURE.map((r) =>
      r.window === 2 ? { ...r, provenance: 'unverified_capture' } : r
    ),
  },
];

export interface FocusedUnitTestCase {
  id: number;
  name: string;
  target: string;
  description: string;
  runTest: () => { passed: boolean; assertionSummary: string };
}

export const STAGE_C_UNIT_TESTS: FocusedUnitTestCase[] = [
  {
    id: 1,
    name: 'test_exact_recorded_output_window_mapping',
    target: 'replay_recorded_detector_outputs',
    description: 'Matches records by exact (window, row_start, row_end) identity across all 5 windows.',
    runTest: () => {
      const res = replayRecordedDetectorOutputs(STAGE_C_SYNTHETIC_FIXTURE, 'synthetic_test');
      const passed = res.ok && res.artifact.windows.length === 5 && res.artifact.windows[4].row_end === 1405;
      return {
        passed,
        assertionSummary: '5 windows mapped exactly to [1000..1405) with batch_size=100',
      };
    },
  },
  {
    id: 2,
    name: 'test_dataset_and_row_range_mismatch_rejected',
    target: 'validate_window_identity',
    description: 'Rejects records when dataset filename or (row_start, row_end) diverges from slice.',
    runTest: () => {
      const mutated = STAGE_C_SYNTHETIC_FIXTURE.map((r) =>
        r.window === 2 ? { ...r, row_start: 1105 } : r
      );
      const res = replayRecordedDetectorOutputs(mutated, 'synthetic_test');
      const passed = !res.ok && res.errors.some((e) => e.code === 'RANGE_MISMATCH');
      return {
        passed,
        assertionSummary: 'Raised RANGE_MISMATCH on Window 2 [1105, 1200)',
      };
    },
  },
  {
    id: 3,
    name: 'test_duplicate_and_missing_window_rejected',
    target: 'validate_completeness',
    description: 'Rejects duplicate window tuples and detects missing production windows.',
    runTest: () => {
      const res = replayRecordedDetectorOutputs(STAGE_C_SYNTHETIC_FIXTURE.slice(0, 4), 'synthetic_test');
      const passed = !res.ok && res.errors.some((e) => e.code === 'MISSING_WINDOW_RECORD');
      return {
        passed,
        assertionSummary: 'Raised MISSING_WINDOW_RECORD when Window 5 [1400, 1405) omitted',
      };
    },
  },
  {
    id: 4,
    name: 'test_invalid_prediction_value_rejected',
    target: 'validate_prediction_domain',
    description: 'Rejects parsed_prediction strings outside {"ATTACK", "BENIGN", null}.',
    runTest: () => {
      const mutated = STAGE_C_SYNTHETIC_FIXTURE.map((r) =>
        r.window === 2 ? { ...r, parsed_prediction: 'SUSPICIOUS' } : r
      );
      const res = replayRecordedDetectorOutputs(mutated, 'synthetic_test');
      const passed = !res.ok && res.errors.some((e) => e.code === 'INVALID_PREDICTION_VALUE');
      return {
        passed,
        assertionSummary: 'Rejected parsed_prediction="SUSPICIOUS" on Window 2',
      };
    },
  },
  {
    id: 5,
    name: 'test_unsupported_provenance_and_stage_b_mock_rejected',
    target: 'validate_provenance',
    description: 'Rejects unknown provenance strings and Stage B mock_configuration_id artifacts.',
    runTest: () => {
      const mutated = STAGE_C_SYNTHETIC_FIXTURE.map((r) =>
        r.window === 1 ? { ...r, provenance: 'mock_replay' } : r
      );
      const res = replayRecordedDetectorOutputs(mutated, 'synthetic_test');
      const passed = !res.ok && res.errors.some((e) => e.code === 'UNSUPPORTED_PROVENANCE');
      return {
        passed,
        assertionSummary: 'Rejected provenance="mock_replay" outside {genuine_recorded, synthetic_test}',
      };
    },
  },
  {
    id: 6,
    name: 'test_ground_truth_derived_and_label_leakage_rejected',
    target: 'validate_label_isolation',
    description: 'Rejects records carrying label_counts, dominant_label, or derived_from_ground_truth.',
    runTest: () => {
      const mutated = STAGE_C_SYNTHETIC_FIXTURE.map((r) =>
        r.window === 4 ? { ...r, binary_truth: 1 } : r
      );
      const res = replayRecordedDetectorOutputs(mutated, 'synthetic_test');
      const passed = !res.ok && res.errors.some((e) => e.code === 'LABEL_LEAKAGE_DETECTED');
      return {
        passed,
        assertionSummary: 'Rejected record containing forbidden field "binary_truth"',
      };
    },
  },
  {
    id: 7,
    name: 'test_detector_status_separation_not_invoked_vs_unparseable',
    target: 'classify_detector_status',
    description: 'Separates NOT_INVOKED, PARSED, UNPARSEABLE, and MISSING without coercing to BENIGN.',
    runTest: () => {
      const res = replayRecordedDetectorOutputs(STAGE_C_SYNTHETIC_FIXTURE, 'synthetic_test');
      if (!res.ok) return { passed: false, assertionSummary: 'Replay failed unexpectedly' };
      const statuses = res.artifact.windows.map((w) => w.detector_status);
      const expected = ['NOT_INVOKED', 'PARSED', 'UNPARSEABLE', 'PARSED', 'NOT_INVOKED'];
      const passed = JSON.stringify(statuses) === JSON.stringify(expected);
      return {
        passed,
        assertionSummary: `Statuses verified: ${statuses.join(', ')}`,
      };
    },
  },
  {
    id: 8,
    name: 'test_non_invoked_with_output_rejected',
    target: 'validate_invocation_consistency',
    description: 'Rejects detector_invoked=false records that supply raw_output or parsed_prediction.',
    runTest: () => {
      const mutated = STAGE_C_SYNTHETIC_FIXTURE.map((r) =>
        r.window === 5 ? { ...r, raw_output: 'stray output' } : r
      );
      const res = replayRecordedDetectorOutputs(mutated, 'synthetic_test');
      const passed = !res.ok && res.errors.some((e) => e.code === 'NON_INVOKED_WITH_OUTPUT');
      return {
        passed,
        assertionSummary: 'Rejected detector_invoked=false with non-null raw_output on Window 5',
      };
    },
  },
  {
    id: 9,
    name: 'test_detector_metric_denominators_exclude_unparseable_and_non_invoked',
    target: 'compute_confusion_metrics',
    description: 'Evaluates detector metrics strictly over the 2 eligible PARSED windows (Population=5, Eligible=2, Excluded=3).',
    runTest: () => {
      const res = replayRecordedDetectorOutputs(STAGE_C_SYNTHETIC_FIXTURE, 'synthetic_test');
      if (!res.ok) return { passed: false, assertionSummary: 'Replay failed' };
      const m = res.artifact.metrics.detector;
      const passed =
        m.population === 5 &&
        m.eligible_predictions === 2 &&
        m.excluded_rows === 3 &&
        m.tp === 2 &&
        m.f1 === 1.0;
      return {
        passed,
        assertionSummary: `Population=${m.population}, Eligible=${m.eligible_predictions}, Excluded=${m.excluded_rows}, TP=${m.tp}, F1=${m.f1?.toFixed(1)}`,
      };
    },
  },
  {
    id: 10,
    name: 'test_monitoring_fallback_accounting',
    target: 'prediction_availability',
    description: 'Uses deterministic monitoring decisions as fallback when detector is NOT_INVOKED or UNPARSEABLE.',
    runTest: () => {
      const res = replayRecordedDetectorOutputs(STAGE_C_SYNTHETIC_FIXTURE, 'synthetic_test');
      if (!res.ok) return { passed: false, assertionSummary: 'Replay failed' };
      const pa = res.artifact.prediction_availability;
      const passed =
        pa.detector_invocations === 3 &&
        pa.detector_predictions === 2 &&
        pa.unparseable_outputs === 1 &&
        pa.monitoring_fallbacks === 3 &&
        pa.overall_predictions === 5;
      return {
        passed,
        assertionSummary: `Invocations=${pa.detector_invocations}, Valid=${pa.detector_predictions}, Fallbacks=${pa.monitoring_fallbacks}, Overall=${pa.overall_predictions}`,
      };
    },
  },
  {
    id: 11,
    name: 'test_provenance_preservation_in_serialized_artifact',
    target: 'serialize_result',
    description: 'Preserves recorded_output_provenance="synthetic_test" in evaluation_configuration.',
    runTest: () => {
      const res = replayRecordedDetectorOutputs(STAGE_C_SYNTHETIC_FIXTURE, 'synthetic_test');
      if (!res.ok) return { passed: false, assertionSummary: 'Replay failed' };
      const passed =
        res.artifact.evaluation_configuration.recorded_output_provenance === 'synthetic_test' &&
        res.artifact.evaluation_configuration.labels_exposed_to_detector === false;
      return {
        passed,
        assertionSummary: 'Artifact preserves provenance="synthetic_test" and labels_exposed_to_detector=false',
      };
    },
  },
  {
    id: 12,
    name: 'test_repeatable_deterministic_serialization',
    target: 'serialize_result',
    description: 'Produces byte-identical JSON output across repeated Stage C replay invocations.',
    runTest: () => {
      const run1 = replayRecordedDetectorOutputs(STAGE_C_SYNTHETIC_FIXTURE, 'synthetic_test');
      const run2 = replayRecordedDetectorOutputs(STAGE_C_SYNTHETIC_FIXTURE, 'synthetic_test');
      const passed =
        run1.ok && run2.ok && JSON.stringify(run1.artifact) === JSON.stringify(run2.artifact);
      return {
        passed,
        assertionSummary: 'Repeated execution produced identical serialized JSON structures',
      };
    },
  },
];

export type DataSourceMode = 'demo_provider' | 'backend_adapter';

export type ProvenanceKind =
  | 'synthetic_test'
  | 'genuine_recorded'
  | 'demo_simulation'
  | 'backend_report';

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NOMINAL';

export type PredictionClass = 'ATTACK' | 'BENIGN';

export type DetectorParseStatus = 'PARSED' | 'UNPARSEABLE' | 'MISSING' | 'NOT_INVOKED';

export type ResponseConfirmationStatus =
  | 'UNCONFIRMED_BACKEND_DISCONNECTED'
  | 'UNCONFIRMED_BACKEND_ACTION_UNAVAILABLE'
  | 'PENDING_BACKEND_CONFIRMATION'
  | 'CONFIRMED_BY_BACKEND'
  | 'NO_ACTION_REQUIRED';

export interface NetworkWindowEvent {
  id: string;
  dataset: string;
  windowIndex: number;
  rowStart: number;
  rowEnd: number;
  flowCount: number;
  timestamp: string;
  protocolSummary: string;
  sourceSubnet: string;
  destinationService: string;
  // Deterministic Monitoring Layer
  monitoringDecision: PredictionClass;
  monitoringSuspicionScore: number;
  monitoringTriggerReason: string;
  // Detector Layer (LangGraph / LLM Agent Node)
  detectorInvoked: boolean;
  detectorStatus: DetectorParseStatus;
  detectorRawOutput: string | null;
  detectorParsedPrediction: PredictionClass | null;
  // Pipeline Resolution
  overallPipelinePrediction: PredictionClass | null;
  usedMonitoringFallback: boolean;
  severity: SeverityLevel;
  // Provenance & Evaluation Truth (Evaluation-Only Isolation)
  provenance: ProvenanceKind;
  sourceLabel: string;
  evaluationOnlyGroundTruth: PredictionClass;
  evaluationOnlyAttackFlows: number;
  evaluationOnlyBenignFlows: number;
  // Threat Response & Mitigation State (Never claims success without backend confirmation)
  proposedMitigationAction: string;
  responseStatus: ResponseConfirmationStatus;
  backendConfirmationReceipt: string | null;
  // Telemetry features for deep inspection
  featureSnapshot: {
    fwdPacketsPerSec: number;
    bwdPacketsPerSec: number;
    synFlagRatio: number;
    rstFlagRatio: number;
    flowDurationMeanMs: number;
    payloadBytesMean: number;
  };
}

export interface AgentNodeSpec {
  id: string;
  stepNumber: string;
  name: string;
  role: string;
  executionMode: 'Deterministic Python' | 'Conditional LangGraph Node' | 'Policy Gate' | 'Offline Harness Only';
  inputContract: string[];
  outputContract: string[];
  isolationGuarantee: string;
  fallbackBehavior: string;
  sampleLatencyMs: number | null;
  invocationsInSlice: number;
  totalWindowsInSlice: number;
}

export interface TimeSeriesTrafficPoint {
  windowLabel: string;
  rowRange: string;
  totalFlows: number;
  suspicionScore: number;
  attackFlowsEvalOnly: number;
  benignFlowsEvalOnly: number;
  detectorInvoked: boolean;
  detectorStatus: DetectorParseStatus;
  overallDecision: PredictionClass | null;
}

export interface ConfusionMatrixSummary {
  layerName: string;
  description: string;
  provenance: ProvenanceKind;
  population: number;
  eligiblePredictions: number;
  excludedWindows: number;
  tp: number;
  tn: number;
  fp: number;
  fn: number;
  accuracy: number | null;
  precision: number | null;
  recall: number | null;
  f1: number | null;
  fpr: number | null;
}

export interface AegisSystemSnapshot {
  dataSourceMode: DataSourceMode;
  backendConnected: boolean;
  backendStatusMessage: string;
  activeDataset: string;
  sliceRange: string;
  batchSize: number;
  provenanceBanner: string;
  events: NetworkWindowEvent[];
  timeSeries: TimeSeriesTrafficPoint[];
  agentNodes: AgentNodeSpec[];
  evaluationMatrices: ConfusionMatrixSummary[];
}

export interface MitigationProposalResult {
  eventId: string;
  proposedAction: string;
  confirmedByBackend: boolean;
  status: ResponseConfirmationStatus;
  message: string;
  timestamp: string;
}

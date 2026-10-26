# Offline evaluation protocol

The offline harness is an evaluation-only layer. It accepts synthetic window
records and deterministic state examples; it does not build or invoke
LangGraph, agents, Gemini, or the evaluator.

## Ground truth

Window labels use the existing `services.data_loader.get_ground_truth`
implementation:

- `Label` is selected through the existing case-insensitive column lookup.
- Missing labels are filled with `Unknown`, then trimmed.
- `Benign` is the negative class.
- If any non-Benign label exists, Benign is excluded from the selection and
  the most frequent attack label is the dominant label. This is not an
  overall majority-label rule.
- If attack counts tie, the existing `max` call uses the label order returned
  by `value_counts` (currently the first listed label).
- A window with no attack labels is dominant `Benign`.
- `evaluation.evaluator.binary_class` maps only dominant `Benign`
  case-insensitively to `BENIGN`; every other dominant label is `ATTACK`.

Ground-truth fields remain in evaluation records only. Agent-facing
observations contain aggregate features and no labels.

## Metric populations

Monitoring metrics use rows with an actual monitoring prediction. Detector
metrics use only invoked windows with a parseable detector prediction.
Overall-pipeline metrics use only actual overall predictions. Missing values
are excluded, never converted to `BENIGN`, and are reported with their
population and exclusion counts. A fallback overall prediction identifies
`monitoring` as its source.

## Run lifecycle

Window statuses remain visible for completed, partial, and incomplete rows.
`run_final_decision_code` is a run-level field and is suppressed unless the
offline result status is `COMPLETED`. Dataset inspection is read-only and
reports unavailable fields explicitly rather than inferring them.

## Stage B replay

`evaluation.offline_harness.replay_dataset_slice` loads one caller-supplied
contiguous slice and uses `create_monitoring_observations` for the existing
aggregate window contract. It passes only the aggregate observation and
window index to an injected deterministic mock. Labels, label counts, and
dominant classes are attached afterward to evaluation-only records.

The fixed local replay used by the Stage B tests is:

- Dataset: `Botnet-Friday-02-03-2018_TrafficForML_CICFlowMeter.parquet`
- Rows: `1000:1405`
- Batch size: `100`
- Windows: four full 100-flow windows and one five-flow partial final
  window

For example, the second window has `Benign: 88` and `Bot: 12`, but its
production dominant label is `Bot` because the loader selects among
non-Benign labels whenever any attack label is present.

The replay does not call `run_pilot`, build a compiled graph, invoke agents,
or call Gemini. A completed partial final window remains a completed
evaluation row and is marked with `partial_final_window`, but is excluded
from the completed-window-only metric population. Interruption creates
explicit `PARTIAL` and `INCOMPLETE` statuses and suppresses the run-level
decision.

## Stage C recorded detector outputs

`replay_recorded_detector_outputs` accepts one explicit record for every
window. Each record must contain:

- Dataset filename
- `window`, `row_start`, and `row_end`
- Boolean `detector_invoked`
- Optional `raw_output`
- Optional `parsed_prediction` (`BENIGN`, `ATTACK`, or null)
- `source`
- `provenance`

The supported provenance values are `genuine_recorded` and `synthetic_test`.
The harness rejects unknown provenance, duplicate or missing window
identities, mismatched ranges, invalid prediction values, records containing
ground-truth fields, and records marked as derived from ground truth.
Recorded outputs are matched by the complete `(window, row_start, row_end)`
identity. Labels are never passed to the monitoring callback or any recorded
detector interface.

An invoked record with raw output but no parsed prediction is retained as
unparseable and excluded from detector metrics. A non-invoked record has no
detector prediction and is also excluded. Overall predictions use monitoring
only as an explicitly reported fallback when no valid detector prediction
exists.

No genuine recorded detector-output fixture currently exists in the project.
The Stage C tests use `synthetic_test` records solely to validate schema,
matching, provenance, isolation, and metric accounting. Their metrics are
not detector-performance results. A future genuine evaluation must supply
locally recorded model output with `genuine_recorded` provenance and an
auditable source.

## Genuine capture workflow

`evaluation.detector_capture.DetectorOutputRecorder` is an isolated,
opt-in boundary utility. It is disabled by default and is not wired into the
production graph in this milestone. A future integration point is immediately
after the existing detector call returns in `agents/detection_agent.py`,
where the caller already has the raw response and evaluator-side window
identity. That integration must pass only the actual detector response and
parsed result; it must not pass labels or monitoring ground truth.

When enabled explicitly with a non-empty source, the recorder stores the
dataset, complete window identity, invocation status, raw output, parsed
prediction, UTC capture timestamp, source, and
`provenance="genuine_recorded"`. It never records non-invocations and does not
alter or replace the detector result. Failed or unparseable genuine
invocations can be recorded with null parsed prediction and raw output as
available. Credentials and API keys are not accepted as fields.

The recorder's unit tests use mocked detector responses only. They do not
produce genuine detector records. Because the production integration is not
enabled, no genuine output has been captured.

## Frontend/API boundary

The existing API can expose serialized run results through its existing result
boundary, but it has no dedicated recorded-output endpoint. A future client
may consume the existing result shape, including `detector_output_provenance`,
`detector_prediction_status`, metric populations, fallback counts, and run
interruption fields. Adding a new route is intentionally out of scope.

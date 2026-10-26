# Agentic AI for Autonomous Threat Detection and Response

## Project architecture

- This is a Python agentic cybersecurity system using LangGraph and Google
  Gemini.
- The workflow is implemented across `agents/` and `core/graph.py`: monitoring,
  detection, analysis, correlation, risk assessment, response, verification,
  recovery monitoring, and a run-level final decision.
- `core/state.py` defines the shared security state. Keep run-level final
  decisions separate from per-window predictions.
- `services/` contains dataset loading, model-service, and run-service
  boundaries. `config/settings.py` contains model configuration.
- `data/raw/` contains local CIC-IDS2018-derived datasets. Do not modify
  dataset files.
- `evaluation/` contains the production evaluator and the deterministic
  offline harness. Follow `evaluation/OFFLINE_EVALUATION_PROTOCOL.md` and
  reuse its schemas and metric conventions.
- `tests/` contains unit, integration, API, service, and offline-evaluation
  tests. The FastAPI application is in `api/`; the separate Streamlit client
  is in `frontend/`.

## Preserve existing behavior

- Before every modification, inspect `git status --short`, relevant diffs, the
  implementation being changed, and its callers.
- Preserve unrelated tracked changes and untracked files. Never use reset,
  clean, checkout, revert, or other destructive Git operations.
- Make the smallest targeted change that solves the requested task and check
  downstream effects.
- Do not change model configuration, prompts, routing, thresholds, dataset
  defaults, row ranges, batch sizes, retry policies, execution limits,
  dependencies, or API contracts unless the request explicitly requires it.
- Use existing interfaces and helpers instead of duplicating orchestration or
  evaluator logic. Handle invalid inputs and failures explicitly.

## Recovery and final decisions

- Preserve the existing recovery policy: increased monitoring severity or
  risk must be able to route through risk assessment back to response.
- Stable or improving monitoring should continue through the existing recovery
  policy without an unnecessary response loop.
- Final decisions require valid completion evidence.
- Interrupted, failed, partial, or incomplete workflows must not be reported as
  successfully mitigated or confirmed benign.
- Inspect the current routing and completion implementation before changing
  these rules, and add focused regression tests for behavioral changes.

## Evaluation integrity

- Keep offline replay separate from live model and graph execution.
- Keep genuine recorded detector outputs, synthetic fixtures, monitoring
  fallbacks, detector-only metrics, and overall-pipeline outcomes distinct.
- Preserve the documented distinction between `PARSED`, `UNPARSEABLE`,
  `MISSING`, and `NOT_INVOKED` detector outputs.
- Use complete window identity (`window`, `row_start`, `row_end`) for recorded
  output matching.
- Never fabricate predictions from labels or use labels to choose rows,
  observations, detector outputs, or predictions.
- Keep labels, label counts, dominant labels, and binary ground truth out of
  detector inputs and captured detector-output records.
- Do not present synthetic metrics as genuine detector performance.
- Reuse `evaluation/offline_harness.py` and its documented result structure
  rather than inventing a competing evaluation format.

## Execution safety

Unless the current request explicitly approves it, do not:

- Call Gemini or any external model API.
- Execute the live LangGraph or production graph.
- Run the live evaluator or `run_pilot()`.
- Execute the root-level `test_gemini.py`.
- Trigger real security-response actions.
- Start expensive or long-running dataset experiments.

Prefer static inspection, unit tests, mocks, and deterministic offline
fixtures. Never claim a live operation or test succeeded unless it actually
ran and returned success.

## Coding standards

- Follow the repository's existing Python style and interfaces.
- Use four spaces for indentation and never tabs in new Python code.
- Keep changes focused and comments rare; explain only non-obvious behavior.
- Validate inputs, reject ambiguous data, and surface errors explicitly.
- Do not add dependencies for routine changes.

## Frontend integration

- `frontend/` is a separate client and must use the actual backend contract.
- Inspect `api/app.py`, `api/schemas.py`, and existing documentation before
  integrating frontend changes.
- Do not assume a separately generated React/TypeScript frontend is connected
  to this Python backend.
- Never invent endpoints, expose secrets in browser code, or present demo data
  as live data.

## Tests and reporting

- Add focused regression tests for behavioral changes.
- Use the safe suite:
  `.\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_*.py"`
- Do not include the unsafe root-level `test_gemini.py` in test runs.
- Compile changed Python files when appropriate.
- Report exact commands, actual outcomes, files changed, unrun tests, and
  remaining risks. Do not commit changes unless explicitly requested.

## Scope control

Work only on the requested task. Do not silently begin governance logging,
NIST mapping, benchmarking, multi-dataset experiments, broad visualization,
deployment, or other future milestones.

## Portable team execution

When the user says **"run the project"**, execute the repository's documented
workflow sequentially rather than merely describing it:

1. Read these instructions and relevant project instructions. Inspect
   `git status --short`, staged and unstaged diffs, configuration, manifests,
   entry points, API routes, frontend scripts, and dataset availability.
   Preserve all staged, unstaged, and untracked work.
2. Preflight the repository's `.venv`, required Python imports, Node.js,
   `npm.cmd`, frontend dependencies, environment configuration, datasets, and
   ports. Use `scripts/preflight.ps1` where applicable. Do not print secrets.
3. Reuse a healthy FastAPI service or start the existing
   `api.app:app` application. Verify health, dataset discovery, dataset schema,
   and CORS for the actual frontend origin.
4. Reuse a healthy Vite service or start the existing frontend script. Verify
   the real backend adapter connection and ensure synthetic demo data is
   clearly separate from backend-originated results. Do not claim browser
   verification from terminal or API checks alone.
5. Inspect the actual `POST /api/v1/runs` schema and implementation before any
   pipeline request. Do not invent routes, parameters, output fields, or
   dataset choices.
6. For any live Gemini, LangGraph, production-evaluator, or real
   security-response execution, ask for explicit authorization first. A plain
   "run the project" request authorizes preflight and service startup only.
   Never run `run_pilot()` or root-level `test_gemini.py` as diagnostics.
7. After explicit authorization, create one valid run through the existing API,
   record its actual run ID, use bounded polling against the registered status
   endpoint, retrieve the registered result endpoint, and stop on failure,
   stalling, or timeout. Do not create duplicate concurrent runs.
8. Run relevant safe offline tests and `git diff --check`. Report exact
   commands, verified results, errors, changed files, and limitations. Stop at
   failed prerequisites instead of continuing blindly.

For portability work, keep `TEAM_SETUP_GUIDE.md`, `.env.example`,
`requirements.txt`, `frontend/package.json`, and
`frontend/package-lock.json` aligned with the actual implementation. Never
distribute `.env`, API keys, tokens, `.venv`, `frontend/node_modules`, caches,
build output, or machine-specific paths. Do not alter model configuration,
prompts, thresholds, dataset defaults, API contracts, or graph logic merely to
make setup easier.

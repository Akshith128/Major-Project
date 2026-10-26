# AEGIS Team Setup and Run Guide

This guide describes the existing **Agentic AI for Autonomous Threat Detection
and Response** project as it is implemented in this repository. It does not
change the LangGraph workflow, model, prompts, thresholds, dataset defaults, or
API contract.

## 1. Prerequisites

The supported team setup is Windows 10 or Windows 11 with:

- Python 3.12 (the included environment was created with CPython 3.12).
- Node.js 20 LTS or newer LTS, with npm available as `npm.cmd`.
- Git for Windows.
- VS Code with a Python extension and a JavaScript/TypeScript extension.
- A Gemini API key for live Gemini-backed runs. Safe tests and API metadata
  checks do not require the key.

The project uses Python, FastAPI, Uvicorn, LangGraph, Gemini, pandas/pyarrow,
and a Vite React/TypeScript dashboard. The existing Streamlit client remains
available as a separate client.

## 2. Extract and open the project

1. Extract the complete ZIP into a local folder without spaces being required.
   For example: `D:\Projects\Major_Project`.
2. Do not copy `.venv`, `frontend\node_modules`, `frontend\dist`, `.env`, or
   other generated files into the ZIP.
3. In VS Code, choose **File > Open Folder** and select the extracted project
   folder.
4. Open a new PowerShell terminal at the repository root:

```powershell
Set-Location 'D:\Projects\Major_Project'
```

Use the actual extraction path on the teammate's computer. No source file
requires the original developer's absolute path.

## 3. Verify tools

Run these commands from the repository root:

```powershell
py --version
python --version
node --version
npm.cmd --version
git --version
```

If `python` is not available but the Python launcher is, use `py -3.12` when
creating the environment. If `node` or `npm.cmd` is missing, install Node.js
20 LTS, reopen PowerShell, and repeat these checks.

## 4. Create and install the Python environment

Create a fresh environment for each computer. Never distribute or reuse the
developer's `.venv`:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

`requirements.txt` contains the repository's pinned Python dependency set.
There is no separate Python lockfile; this pinned manifest is the project's
reproducibility mechanism. Do not install the root-level `test_gemini.py` as a
test command.

Verify the important imports without calling Gemini:

```powershell
.\.venv\Scripts\python.exe -c "import fastapi, uvicorn, pandas, pyarrow, langgraph, langchain_google_genai; print('backend imports OK')"
```

## 5. Install the React dependencies

The frontend is a Vite React/TypeScript application. The committed
`frontend\package-lock.json` is the npm lockfile and must remain synchronized
with `frontend\package.json`.

```powershell
Set-Location frontend
npm.cmd ci
npm.cmd run lint
npm.cmd run build
Set-Location ..
```

Use `npm.cmd ci` for a clean installation from the lockfile. If npm reports a
peer-dependency conflict, first confirm Node/npm versions and the lockfile are
present; do not use `--force` or `--legacy-peer-deps` unless the team explicitly
decides to update and document dependency resolution.

## 6. Configure credentials safely

Copy the example file and edit it locally:

```powershell
Copy-Item .env.example .env
notepad .env
```

Set `GOOGLE_API_KEY` to a valid Gemini key. Keep `.env` local and never commit,
email, or include it in the ZIP. The backend reads this value through
`config\settings.py` and `services\llm_service.py`. The configured model is
`gemini-3.6-flash`.

The React dashboard must not contain a Gemini key. Its optional
`frontend\.env.local` may contain only non-secret frontend configuration such as
`VITE_AEGIS_API_BASE_URL=http://127.0.0.1:8000`.

## 7. Verify datasets

The current repository includes these files under `data\raw`:

```text
Botnet-Friday-02-03-2018_TrafficForML_CICFlowMeter.parquet
Bruteforce-Wednesday-14-02-2018_TrafficForML_CICFlowMeter.parquet
DDoS1-Tuesday-20-02-2018_TrafficForML_CICFlowMeter.parquet
DDoS2-Wednesday-21-02-2018_TrafficForML_CICFlowMeter.parquet
DoS1-Thursday-15-02-2018_TrafficForML_CICFlowMeter.parquet
DoS2-Friday-16-02-2018_TrafficForML_CICFlowMeter.parquet
Infil1-Wednesday-28-02-2018_TrafficForML_CICFlowMeter.parquet
Infil2-Thursday-01-03-2018_TrafficForML_CICFlowMeter.parquet
Web1-Thursday-22-02-2018_TrafficForML_CICFlowMeter.parquet
Web2-Friday-23-02-2018_TrafficForML_CICFlowMeter.parquet
```

They are large files. If distribution restrictions require omitting them, obtain
the same CIC-IDS2018-derived Parquet files from the project owner and place them
directly in `data\raw`; filenames must remain unchanged. Do not rename,
reorder, relabel, or modify the data.

Check presence and basic readability:

```powershell
Get-ChildItem data\raw -File -Filter *.parquet |
  Select-Object Name, Length
.\.venv\Scripts\python.exe -c "from services.data_loader import load_network_data; from pathlib import Path; p=Path('data/raw/Web2-Friday-23-02-2018_TrafficForML_CICFlowMeter.parquet'); d=load_network_data(str(p)); print(p.name, len(d), 'rows', len(d.columns), 'columns')"
```

The API's dataset and schema endpoints perform the authoritative application
level discovery and schema check.

Run records created through `POST /api/v1/runs` are persisted in
`data\runs.json` so completed and interrupted reports remain available after a
backend restart. This file is local runtime state, is excluded from the team
ZIP, and is ignored by Git. A run that was created before persistence was
added cannot be recovered without rerunning it.

## 8. Safe tests and preflight

Run the repository's safe test suite from the root:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_*.py"
```

Do not run the root-level `test_gemini.py` as part of discovery. It is not the
safe offline test path.

The reusable preflight checks do not call Gemini, start the graph, run the
evaluator, or trigger response actions:

```powershell
.\scripts\preflight.ps1
```

If the local PowerShell execution policy blocks repository scripts, use a
process-scoped bypass; this does not change the machine or user policy:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\preflight.ps1
```

To require a configured local Gemini key before a planned, separately approved
live run:

```powershell
.\scripts\preflight.ps1 -RequireGeminiKey
```

## 9. Start the backend

Open a terminal at the repository root and run:

```powershell
.\.venv\Scripts\python.exe -m uvicorn api.app:app --reload --host 127.0.0.1 --port 8000
```

Reuse a healthy backend instead of starting a duplicate. The FastAPI
application is `api.app:app`.

## 10. Start the React dashboard

In a second terminal:

```powershell
Set-Location frontend
npm.cmd run dev
```

The Vite development server is configured for
`http://localhost:3000`. The FastAPI CORS configuration explicitly permits both
`http://localhost:3000` and `http://127.0.0.1:3000`.

The optional Streamlit client can be started separately, but it is not the
React dashboard:

```powershell
.\.venv\Scripts\python.exe -m streamlit run frontend\streamlit_app.py
```

## 11. Verify API and frontend connectivity

From another PowerShell terminal:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/v1/health
$datasets = Invoke-RestMethod http://127.0.0.1:8000/api/v1/datasets
$datasetId = $datasets.datasets[0].dataset_id
$encoded = [uri]::EscapeDataString($datasetId)
Invoke-RestMethod "http://127.0.0.1:8000/api/v1/datasets/$encoded/schema"
```

Verify CORS without revealing credentials:

```powershell
Invoke-WebRequest -Method Options `
  -Uri http://127.0.0.1:8000/api/v1/health `
  -Headers @{
    Origin = 'http://localhost:3000'
    'Access-Control-Request-Method' = 'GET'
  } | Select-Object StatusCode, Headers
```

Open `http://localhost:3000`, select **Backend Adapter**, and confirm that the
dashboard reports backend-originated data. The separate demo provider must
remain visibly synthetic; it is not a live result. Terminal/API checks do not
prove browser rendering, so report browser verification separately.

## 12. Create and monitor a pipeline run

The registered run endpoint is synchronous in the current implementation:
`POST /api/v1/runs` calls the existing `RunService`, which delegates to
`evaluation.evaluator.run_pilot`. It does not create a replacement workflow.
The status and result endpoints still exist and should be used with the returned
run ID.

Inspect the dataset list first and use an actual `dataset_id`. The request
schema is:

```powershell
$body = @{
  dataset_id = $datasetId
  start_row = 0
  end_row = 800
  batch_size = 100
  max_graph_executions = 1
} | ConvertTo-Json

$run = Invoke-RestMethod `
  -Method Post `
  -Uri http://127.0.0.1:8000/api/v1/runs `
  -ContentType 'application/json' `
  -Body $body
$run.run_id
```

The defaults are defined by `evaluation\evaluator.py` and
`api\schemas.py`; do not invent alternate values. If the API returns
`RUNNING`, poll the actual status endpoint with a bounded loop:

```powershell
for ($attempt = 1; $attempt -le 30; $attempt++) {
  $status = Invoke-RestMethod "http://127.0.0.1:8000/api/v1/runs/$($run.run_id)"
  $status | ConvertTo-Json -Depth 5
  if ($status.status -in @('COMPLETED', 'INTERRUPTED', 'FAILED')) { break }
  Start-Sleep -Seconds 2
}
$result = Invoke-RestMethod "http://127.0.0.1:8000/api/v1/runs/$($run.run_id)/result"
$result | ConvertTo-Json -Depth 20
```

The current API normally returns a completed status from `POST` because the
service executes synchronously. A failed run has no successful result.

## 13. Interpret returned fields

Only report fields actually returned by the API:

- `dataset`, row range, batch size, selection, and window counts describe the
  evaluated data scope.
- `monitoring_metrics` are deterministic monitoring predictions.
- `llm_metrics` cover parsed detector outputs when the detector was invoked.
- `pipeline_metrics` use detector output when available and monitoring fallback
  otherwise; they are not detector-only metrics.
- Each row separates `ground_truth_binary_class`,
  `monitoring_anomaly_prediction`, `llm_detection_prediction`,
  `llm_detection_invoked`, and `overall_pipeline_prediction`.
- `run_status` and `interruption_reason` identify completion or interruption.
- `run_final_decision_code` is a run-level conclusion, not a per-window
  prediction. Missing, incomplete, interrupted, or uncertain evidence must not
  be described as benign or successfully mitigated.
- Severity, risk, response, verification, recovery, and final-decision values
  are evidence-dependent. Do not infer fields absent from the returned result.

Live Gemini responses can vary because of model/API versions, quota, service
availability, and credentials. Do not promise bit-for-bit identical live
outputs. The safe offline tests and deterministic fixtures are the baseline for
comparing project receipt and workflow behavior.

## 14. Troubleshooting

- **PowerShell blocks activation:** activation is optional. Use
  `.\.venv\Scripts\python.exe` directly. If activation is required for local
  work, run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` in an
  administrator-approved environment.
- **PowerShell blocks a setup script:** use the process-scoped
  `powershell.exe -NoProfile -ExecutionPolicy Bypass -File ...` command shown
  above. Do not lower the machine-wide execution policy.
- **Python or pip missing:** install Python 3.12, reopen PowerShell, recreate
  `.venv`, and rerun the install commands.
- **Node/npm not found:** install Node.js 20 LTS, verify `node --version` and
  `npm.cmd --version`, then reopen the terminal.
- **Node is installed but not recognized:** use the installed Node directory in
  the current PowerShell session, then rerun the frontend commands:
  `$env:Path = 'C:\Program Files\nodejs;' + $env:Path`. Do not hardcode this
  machine-specific path into project source files.
- **npm peer-dependency conflict:** use the committed lockfile and matching
  Node LTS first; do not force-install silently.
- **Missing dataset:** obtain the exact file from the project owner and place it
  in `data\raw`. Verify the filename through `/api/v1/datasets`.
- **Invalid credentials:** confirm `.env` contains a non-empty
  `GOOGLE_API_KEY`; never paste it into source, browser code, or support logs.
- **CORS or `Failed to fetch`:** confirm the backend is on `127.0.0.1:8000`,
  the frontend is on port `3000`, and the preflight command above includes the
  expected allow-origin header.
- **Port conflict:** inspect with
  `Get-NetTCPConnection -LocalPort 8000,3000 -State Listen`. Reuse a healthy
  process or stop only a process you own; do not start duplicate servers.
- **Run conflict:** the API rejects a second concurrent run with HTTP 409.
  Wait for the existing run to reach a terminal status.

## 15. Package a distributable ZIP

From the repository root, check `git status --short` and use the safe packaging
script. It creates a temporary sibling staging directory, excludes local
secrets and generated environments, and removes only the staging directory it
created:

```powershell
.\scripts\package-team.ps1 -DestinationPath ..\AEGIS-team.zip
```

Before distribution, confirm the archive does **not** contain these paths:

- `.env` or any API key/token.
- Any local `.env.*` file other than the committed `.env.example`.
- `.venv`, `venv`, or `env`.
- `frontend\node_modules` or `frontend\dist`.
- `__pycache__`, test caches, logs, or machine-specific files.

The archive should retain source code, tests, `requirements.txt`,
`frontend\package.json`, `frontend\package-lock.json`, setup documentation,
and the required `data\raw` datasets when redistribution is permitted.

## 16. Verification result rules

Record each check as one of these states:

- **PASS:** the exact command ran and returned the expected result.
- **FAIL:** the command ran and returned an error, or a required prerequisite
  was absent. Do not continue into dependent steps.
- **NOT RUN:** the check was intentionally skipped, such as a live Gemini run
  without explicit authorization or a frontend build when Node.js/npm is not
  installed.

Terminal/API checks are not browser verification. Only report the dashboard as
browser-verified after opening it and confirming the Backend Adapter in a
browser. A successful health request alone does not prove that the React
dashboard rendered or loaded backend data.

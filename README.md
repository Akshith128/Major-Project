# AEGIS — Agentic AI for Autonomous Threat Detection and Response

**Enhancing Cybersecurity Governance and Digital Trust**

AEGIS watches network traffic (the CIC-IDS2018 flow dataset) with a team of five
AI agents built on LangGraph. Each window of traffic is triaged, reasoned about
by Gemini, risk-scored, given a containment plan, and passed through a
governance policy that keeps a human in the loop and writes every decision to a
tamper-evident audit trail.

```
monitoring ──suspicious──▶ detection ──threat──▶ risk ─▶ response ─┐
    │                          │                                   ▼
    └──────── clean ───────────┴────────── no threat ─────────▶ governance
```

| Agent | How it decides | Output |
|---|---|---|
| Monitoring | Deterministic homogeneity score (attack traffic repeats one flow pattern) | score, suspicious, signals |
| Detection | Gemini reads label-free features; rule fallback | threat, attack type, confidence, reasoning |
| Risk | Confidence × attack impact, escalated for repeated incidents in the run | risk 0–100, severity |
| Response | Gemini adapts a per-attack playbook; playbook fallback | recommended actions (never auto-executed) |
| Governance | Policy `AEGIS-GOV-1` | `NO_ACTION`, `AUTO_APPROVED` or `PENDING_REVIEW` |

**Digital trust guarantees**

- Agents see only aggregate traffic features. Ground-truth labels are attached
  after the agents finish and are used only for evaluation.
- High/critical severity, confidence below 80, or any rule-based decision needs
  an analyst's approval in the console.
- Every run start, window decision and analyst review is SHA-256 hash-chained;
  `GET /api/runs/{id}/audit/verify` detects any edit, deletion or reordering.
- Each decision records whether it came from Gemini or the rule fallback.

## Project layout

```
aegis/          backend package
  data.py         parquet → label-free traffic windows (+ separate ground truth)
  agents.py       the five agents
  graph.py        LangGraph workflow
  llm.py          Gemini client (JSON replies) and rules-only mode
  runs.py         run execution, storage (data/runs/*.json), analyst reviews
  audit.py        hash-chained audit trail
  evaluation.py   precision / recall / F1 against ground truth
  api.py          FastAPI service
frontend/       React + Tailwind console (personalized operator sign-in)
tests/          unit + API tests
main.py         command-line run
data/raw/       CIC-IDS2018 parquet files (not in git)
```

## Setup (Windows, Python 3.12, Node 20+)

```powershell
py -3.12 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
npm.cmd --prefix frontend install
Copy-Item .env.example .env   # then put your Gemini key in GOOGLE_API_KEY
```

Place the CIC-IDS2018 parquet files (e.g.
`DDoS1-Tuesday-20-02-2018_TrafficForML_CICFlowMeter.parquet`) in `data\raw\`.
Without a Gemini key everything still runs in rules-only mode.

## Run

Backend and console, in two terminals:

```powershell
.venv\Scripts\python.exe -m uvicorn aegis.api:app --port 8000
npm.cmd --prefix frontend run dev
```

Open http://localhost:3000, enter your name and role, then start a run from
**Overview**. Review pending responses under **Incidents** and check the audit
trail and evaluation under **Governance**.

Command line only:

```powershell
.venv\Scripts\python.exe main.py --dataset DDoS1-Tuesday-20-02-2018_TrafficForML_CICFlowMeter.parquet --windows 12 --mode rules
```

`--mode auto` (default) uses Gemini when a key is set, `gemini` requires it,
`rules` never calls it.

## Tests

```powershell
.venv\Scripts\python.exe -m unittest discover -s tests -t .
npm.cmd --prefix frontend run lint
```

## API

| Method | Path | |
|---|---|---|
| GET | `/api/health` | status, Gemini configuration, dataset count |
| GET | `/api/datasets` | available parquet files |
| POST | `/api/runs` | start a run `{dataset_id, windows, window_size, sampling, start_row, mode, operator}` |
| GET | `/api/runs` · `/api/runs/{id}` | run list · full run with windows, evaluation, audit |
| POST | `/api/runs/{id}/windows/{index}/review` | analyst decision `{decision: APPROVED\|REJECTED, operator, note}` |
| GET | `/api/runs/{id}/audit/verify` | verify the audit hash chain |

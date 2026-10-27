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
  the approval of a signed-in reviewer. Operators have real accounts
  (PBKDF2-hashed passwords); the server checks each role's permissions and
  writes the account, not a typed name, into the audit trail.
- Every run start, window decision and review is SHA-256 hash-chained and
  HMAC-signed with a key kept outside the run files, and the head of each chain
  is signed into a separate checkpoint log. `GET /api/runs/{id}/audit/verify`
  detects edits, deletions, reordering, a recomputed chain and a truncated tail.
- Each LLM decision records the model version actually served, temperature,
  prompt template, prompt and input hashes, latency, tokens and whether the
  reply passed schema validation. Replies that fail validation fall back to
  rules, which governance always escalates.
- A security manager can pause AEGIS (EU AI Act Art. 14(4)(e) "stop button"):
  no run can start and a running one stops after its current window.

## Evaluation and what it shows

Every run scores the monitoring gate, the full pipeline and two baselines on
the same windows: a Random Forest trained on the *other* day-files (the test
day is never seen in training) and the single-feature rule "unique TCP window
ratio ≤ 0.05". It reports MCC, balanced accuracy, attack prevalence, 95%
intervals, McNemar tests, ROC/PR-AUC of the monitoring score, calibration of
Gemini's confidence (ECE, Brier), governance load and cost.

A single 10-window run cannot support a detection claim (±28 points on
accuracy), so use the multi-day benchmark for results:

```powershell
.venv\Scripts\python.exe -m aegis.benchmark                          # rules, 50 windows × 8 day-files × 3 seeds
.venv\Scripts\python.exe -m aegis.benchmark --ablate-tcp-window      # drop the suspected shortcut feature
.venv\Scripts\python.exe -m aegis.benchmark --mode gemini --seeds 1 --repeats 3   # LLM variance (uses quota)
.venv\Scripts\python.exe -m aegis.benchmark --label-threshold 0.1    # sensitivity to the window-labelling rule
```

Results go to `reports/benchmark-*.md` and `.json`. In rules mode (1,200
windows, prevalence 0.19) the pipeline reached MCC 0.66 [0.62, 0.70] and the
monitoring gate 0.56; the TCP-window rule alone matched the gate (McNemar
p = 1.0), and without that feature the rules pipeline fell to MCC 0.40. A
Random Forest trained on other days scored MCC 0.21: each day-file holds a
different attack, so cross-day detection is hard for every method.

**Current results** (fresh windows, seeds 3–4): the hybrid detector, a
one-class SVM trained on normal traffic, without the TCP-window shortcut and
gated by the homogeneity score, reaches MCC 0.74. That compares with 0.65 for
the previous detector and 0.66 for the rules, with false alarms down from 19% to
12%. Attack families are named 57% correctly for never-seen tools and 98% once
analysts have confirmed similar incidents. See `reports/detector-improvement-results.md`
and `reports/typing-improvement-results.md`.

**Hybrid mode** (`mode: "hybrid"`, or `--mode hybrid` in the benchmark):
`aegis/anomaly.py` trains a one-class SVM on *normal* traffic windows only
(from the same capture, never overlapping the windows being judged, or with
`--baseline cross-day` from other day-files). It flags windows outside a fixed
5% false-alarm budget and decides the verdict. Gemini then explains the window,
names the attack family and drafts the response. It sees the deviating features
and the most similar known incidents from other days, may raise severity but
never lower it, and ATT&CK techniques come from a fixed table. On the same
400 windows the detector scored MCC 0.56, against 0.67 for rules and 0.63 for
Gemini. With the TCP-window shortcut removed it scored 0.61, against 0.42 for
rules. Attack families from similar-incident retrieval were 62% correct, against
7–11% from Gemini. Full comparison: `reports/hybrid-evaluation.md`.
`--no-llm` benchmarks the detector without spending Gemini quota.

**Threats to validity.** The original CSE-CIC-IDS2018 labels have documented
errors (Engelen et al. 2021; Liu et al. 2022). AEGIS flags them per day-file
(`data.DATASET_NOTES`): Infiltration days are excluded from the benchmark and
baseline training, web-attack days have almost no attack windows, and the
broken FTP-Patator and SlowHTTPTest attacks are noted. The parquet files have
no timestamps, so windows follow the release's row order. The research review
behind these changes is in `reports/Agentic AI threat detection review.md`.

## Project layout

```
aegis/          backend package
  data.py         parquet → label-free traffic windows (+ separate ground truth)
  agents.py       the five agents
  graph.py        LangGraph workflow
  llm.py          Gemini client (JSON replies, model version, tokens) and rules-only mode
  runs.py         run execution, storage (data/runs/*.json), reviews
  audit.py        hash-chained, HMAC-signed audit trail with checkpoints
  anomaly.py      benign-trained anomaly detector + similar-incident retrieval (hybrid)
  baselines.py    Random Forest (other day-files) and TCP-window rule baselines
  evaluation.py   MCC, intervals, McNemar, AUC, calibration, governance, cost
  benchmark.py    multi-day, multi-seed evaluation (python -m aegis.benchmark)
  auth.py         accounts, sessions, role permissions
  users.py        account management CLI (python -m aegis.users)
  control.py      pause / resume stop control
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
Copy-Item .env.example .env   # choose the reasoning model (AEGIS_LLM_PROVIDER)
```

Place the CIC-IDS2018 parquet files (e.g.
`DDoS1-Tuesday-20-02-2018_TrafficForML_CICFlowMeter.parquet`) in `data\raw\`.
**Reasoning model.** The default is a free local model through
[Ollama](https://ollama.com): no quota, no cost, and no traffic data leaves the
machine. Install Ollama, then run `ollama pull qwen2.5:3b`. Alternatively set
`AEGIS_LLM_PROVIDER=groq` with a `GROQ_API_KEY` (hosted free tier, rate limited)
or `gemini` with a `GOOGLE_API_KEY`. Without any model everything still runs:
rules mode, and hybrid mode with detector-only explanations.

Create at least one operator account (you are asked for a password):

```powershell
.venv\Scripts\python.exe -m aegis.users add yourname --role manager --name "Your Name"
```

Roles: `analyst` starts runs and reviews, `responder` reviews, `manager` also
pauses AEGIS, `researcher` is read-only. Signing and session keys are generated
once in `%USERPROFILE%\.aegis\` unless `AEGIS_AUDIT_KEY` / `AEGIS_AUTH_SECRET`
are set.

## Run

Backend and console, in two terminals:

```powershell
.venv\Scripts\python.exe -m uvicorn aegis.api:app --port 8000
npm.cmd --prefix frontend run dev
```

Open http://localhost:3000, sign in with your account, then start a run from
**Overview**. Review pending responses under **Incidents** and check the audit
trail and evaluation under **Governance**.

Command line only:

```powershell
.venv\Scripts\python.exe main.py --dataset DDoS1-Tuesday-20-02-2018_TrafficForML_CICFlowMeter.parquet --windows 12 --mode rules
```

`--mode auto` (default) uses the reasoning model when it is available, `llm`
requires it, `rules` never calls it, `hybrid` lets the anomaly detector decide and
the reasoning model explain.

## Tests

```powershell
.venv\Scripts\python.exe -m unittest discover -s tests -t .
npm.cmd --prefix frontend run lint
```

## API

| Method | Path | |
|---|---|---|
All endpoints except health and login need `Authorization: Bearer <token>`.

| Method | Path | |
|---|---|---|
| GET | `/api/health` | status, Gemini configuration, dataset count, accounts exist, paused |
| POST | `/api/auth/login` | `{username, password}` → session token |
| GET | `/api/auth/me` | signed-in account and permissions |
| GET · POST | `/api/control` | stop-control state · pause/resume `{paused, reason}` (manager) |
| GET | `/api/datasets` | parquet files with attack share and known label problems |
| POST | `/api/runs` | start a run `{dataset_id, windows, window_size, sampling, start_row, mode, seed}` (analyst, manager) |
| GET | `/api/runs` · `/api/runs/{id}` | run list · full run with windows, baselines, evaluation, audit |
| POST | `/api/runs/{id}/windows/{index}/review` | `{decision: APPROVED\|REJECTED, note}` (analyst, responder, manager) |
| GET | `/api/runs/{id}/audit/verify` | verify hashes, signatures and the checkpoint |

# Attack-family naming: before and after

The test used fresh windows that were never inspected during development: benchmark seeds 1 and 2, 800 windows (50 per usable day-file per seed). All designs used the same detector and the local model qwen2.5:3b (Ollama). Caught true attacks: 139 (93 DDoS, 21 DoS, 13 Brute Force, 12 Botnet).

- **Old design** (commit `4fcc4e5`): the model names the family, given similar incidents.
- **New design**: a 3-nearest-neighbour vote over the incident memory names the family, and the model only explains it.
- **New + memory**: the same, with incidents from earlier in the same capture treated as already confirmed by an analyst. They must end at least 5,000 rows before the judged window.

Raw results are in `reports/final-*.json`. Scoring: `python scripts/typing_report.py old=reports/final-old-design.json new=reports/final-new-novel.json memory=reports/final-new-memory.json --seeds 1 2`.

## Family naming

| | Exact family [95% CI] | Answerable families* | Coarse group | Macro-F1 |
|---|---|---|---|---|
| Old: the model names it | 50% [41, 58] | 61% | 73% | 0.21 |
| **New: memory vote, model explains** | **55%** [47, 63] | **68%** | **82%** | **0.29** |
| **New + analyst-confirmed incidents** | **97%** [93, 99] | **96%** | **100%** | **0.97** |

\* Excludes Botnet and Brute Force. Each appears on one usable day-file only, so no example exists when its day is judged.

Paired McNemar tests on the same 139 windows:

- **Old vs new:** 18 vs 26 windows, p = 0.29. The new design is better on every measure, but the exact-family gain is not yet statistically significant.
- **Old vs new + memory:** 2 vs 68, p < 0.001.

What changed in the mistakes:

- **Old:** errors scattered across DDoS↔DoS, DDoS→Botnet, Brute Force→DoS and Botnet→DDoS.
- **New:** the errors left are DDoS→DoS (37), Brute Force→DoS (13) and Botnet→DDoS (12). The first stays inside the volumetric-flood group, which DoS and DDoS share, hence the higher coarse-group accuracy. The other two are the families with no other day-file to learn from.
- **With memory:** only 4 errors remain (DDoS→DoS).

## Everything else (seeds 1–2)

Detection is identical in both designs because the same detector decides: MCC 0.64 [0.58, 0.69], recall 0.89, false alarm rate 0.15.

| | Old | New |
|---|---|---|
| Explanations answered | 375 / 375 | 238 / 238 |
| Schema failures | 0 | 0 (the JSON schema is now enforced by Ollama) |
| Median / p95 latency per call | 2.08 s / 3.08 s | 2.07 s / 2.83 s |
| Tokens per window | 480 | 428 |
| Review load | 0.31 | 0.30 |

## How this was kept honest

- **Design chosen on separate development windows.** `scripts/typing_experiment.py` used sampling seeds 11 and 21. There, the richer "behavioural" feature set the literature suggested did worse (37% vs 43%), because each day-file uses a different attack tool. Distance-based "Unknown" detection also failed (0–22% recall on unseen families), so neither was adopted.
- **Benchmark seeds 1–2 used only once,** after the design was frozen.
- **One discarded run.** The first old-design run lost its Ollama server mid-run, so 199 of its explanations fell back. It was discarded and re-run in full.

## What this means

1. **Never-seen attack tools:** family naming is capped by the data. Every day-file holds one tool, and two families exist on one day-file only. The new design is modestly better: +5 points exact, +9 coarse group, and higher macro-F1.
2. **Repeats of attacks an analyst has already confirmed:** the incident memory names the family almost perfectly (97%). In the console, approving a review with the right family adds it to that memory.
3. **The language model's job:** explain and draft responses, not classify.

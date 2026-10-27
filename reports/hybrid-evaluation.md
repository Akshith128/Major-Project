# Rules vs Gemini vs hybrid on identical windows

All results use the same 400 windows: 50 per usable day-file × 8 day-files, seed 0, 100 flows per window, attack prevalence 0.19. Infiltration days are excluded. Raw results are in `reports/benchmark-*-seed0*.json` and `reports/benchmark-hybrid-*.json`. Pairwise tables come from `scripts/compare_benchmarks.py`.

## Detection

| Pipeline | MCC [95% CI] | Recall | False alarm rate | TP / FP / FN / TN |
|---|---|---|---|---|
| Rules (monitoring gate + score ≥ 0.75) | **0.674** [0.60, 0.75] | 0.92 | **0.14** | 70 / 46 / 6 / 278 |
| Gemini decides | 0.625 [0.57, 0.69] | **1.00** | 0.23 | 76 / 74 / 0 / 250 |
| Hybrid, same-network normal baseline | 0.564 [0.48, 0.64] | 0.90 | 0.21 | 68 / 69 / 8 / 255 |
| Hybrid, cross-day normal baseline | 0.551 [0.46, 0.65] | 0.76 | 0.15 | 58 / 47 / 18 / 277 |
| Random Forest trained on other days | 0.225 [0.10, 0.35] | 0.20 | 0.05 | — |
| TCP-window rule alone | 0.516 [0.45, 0.58] | 0.96 | 0.31 | — |

Paired McNemar tests on the same windows:

- Rules vs hybrid: rules alone right on 48 windows, hybrid alone right on 23 (p = 0.004).
- Gemini vs hybrid: 42 vs 39 (p = 0.82, no difference).
- Rules vs Gemini: 28 vs 6 (p = 0.0002).

### With the suspected TCP-window shortcut removed

| Pipeline | MCC | Recall | False alarm rate |
|---|---|---|---|
| Rules | 0.421 [0.32, 0.52] | 0.65 | 0.17 |
| Hybrid, same-network | **0.612** [0.54, 0.68] | 0.99 | 0.23 |

The rules pipeline's lead depends on the TCP initial-window feature, which the literature flags as a testbed artefact. The benign-trained detector does not depend on it: it gets better when the feature is removed.

## Attack typing (of the true attacks each pipeline caught)

| Who names the attack family | Correct |
|---|---|
| Rules | 0 / 70 (always "Unknown") |
| Gemini deciding and typing | 8 / 76 (11%) |
| Gemini explaining the detector's verdict (hybrid, answered calls) | 3 / 45 (7%) |
| Nearest known incidents from other days (retrieval, all hybrid windows) | **42 / 68 (62%)** |
| Retrieval, cross-day baseline | 41 / 58 (71%) |

Gemini's errors were systematic. It called DDoS floods "DoS" or "Port Scan", Bot traffic "DoS", and SSH brute force "Botnet" or "DoS". Retrieval's errors are mostly structural: Botnet and Brute Force appear on only one day-file each, so a leave-that-day-out lookup has no example of them to match.

## Trust and cost

| | Gemini decides | Hybrid |
|---|---|---|
| LLM calls | 327 | 274 |
| Median / p95 latency | 7.6 s / 16.9 s | 6.1 s / 8.4 s |
| Tokens per window | 335 | 189 |
| Fallbacks | 19% of detections | 87 of 137 explanations (quota exhausted) |
| Confidence calibration | ECE 0.35; right 57% of the time at confidence ≥ 80 | Confidence is the detector's empirical p-value against normal traffic, not a self-report |
| Auto-approvals | 3, one of them benign | 0 |

## Local model (Ollama, qwen2.5:3b) vs Gemini

Same 400 windows. Raw results: `reports/benchmark-ollama-seed0.json` and `reports/benchmark-hybrid-same-network-ollama.json`.

**When the language model decides:**

| | Gemini | Ollama qwen2.5:3b |
|---|---|---|
| MCC [95% CI] | **0.625** [0.57, 0.69] | 0.544 [0.48, 0.60] |
| Recall | 1.00 | 1.00 |
| False alarm rate | **0.23** | 0.31 |
| Attack typing | 8/76 (11%) | 9/76 (12%) |
| Calibration (ECE) | 0.35 | 0.38 |
| Schema failures · fallbacks | 0 · 19% (quota) | 19 · 11% |
| Median / p95 latency | 7.6 s / 16.9 s | **1.6 s / 2.2 s** |

The local model said "threat" to every window the monitoring gate passed on. Its verdicts equal the gate's exactly, so it added no detection judgement. Gemini was right on 27 windows where Ollama was wrong; the reverse never happened (p < 0.001).

**In the hybrid pipeline** (the detector decides, so detection is identical):

| | Gemini | Ollama qwen2.5:3b |
|---|---|---|
| Explanations answered | 50 of 137 (quota) | **137 of 137** |
| Attack typing when the model answered | 3/45 (7%) | **37/68 (54%)** |
| Retrieval of similar incidents alone | 42/68 (62%) | 42/68 (62%) |
| Median / p95 latency | 6.1 s / 8.4 s | **2.1 s / 2.7 s** |

Given the similar-incident evidence, the small local model mostly followed it (54% correct), while Gemini mostly ignored it (7%). Neither beat the retrieval vote on its own (62%).

## Caveats

- **Free-tier quota.** The free-tier Gemini quota ran out during the hybrid run (a later test call returned "quota exceeded"). So the hybrid typing figure mixes 45 Gemini answers with 23 retrieval fallbacks, and part of the Gemini run's 19% fallback rate is probably the same cause.
- **Threshold exploration.** The detector design (normal baseline, 5% false-alarm budget) was fixed after two exploratory looks at per-day results on these test windows. Its numbers are therefore mildly optimistic, and the next run should use fresh seeds.
- **Small sample.** One seed and 400 windows; Botnet (11), Brute Force (8) and DoS (11) attack windows are few.
- **Dataset.** Original CSE-CIC-IDS2018 labels, with the documented errors listed in `aegis/data.py`.

## Conclusions

1. **No single pipeline wins everything.** On raw detection, rules score highest, but only by leaning on the shortcut feature. Without it, the benign-trained detector is clearly better (0.61 vs 0.42) and needs no attack labels.
2. **Gemini is not a reliable classifier of attack families from aggregate flow features.** It was 7–11% correct here. Retrieval of similar known incidents was 62–71% correct, at no API cost.
3. **The free local model is a workable replacement for Gemini** in the role that matters: explaining and drafting responses in hybrid mode. It answered every call, about 3× faster, at no cost. As a decision-maker it was worse than Gemini and rubber-stamped the gate.
4. **What fits the evidence is a split of roles:**
   - the detector decides;
   - retrieval names the family and the ATT&CK techniques;
   - Gemini writes the explanation and the response plan from that evidence, and may raise but never lower severity;
   - a human approves.

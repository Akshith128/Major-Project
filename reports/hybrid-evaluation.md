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

## Caveats

- **Free-tier quota.** The free-tier Gemini quota ran out during the hybrid run (a later test call returned "quota exceeded"). So the hybrid typing figure mixes 45 Gemini answers with 23 retrieval fallbacks, and part of the Gemini run's 19% fallback rate is probably the same cause.
- **Threshold exploration.** The detector design (normal baseline, 5% false-alarm budget) was fixed after two exploratory looks at per-day results on these test windows. Its numbers are therefore mildly optimistic, and the next run should use fresh seeds.
- **Small sample.** One seed and 400 windows; Botnet (11), Brute Force (8) and DoS (11) attack windows are few.
- **Dataset.** Original CSE-CIC-IDS2018 labels, with the documented errors listed in `aegis/data.py`.

## Conclusions

1. **No single pipeline wins everything.** On raw detection, rules score highest, but only by leaning on the shortcut feature. Without it, the benign-trained detector is clearly better (0.61 vs 0.42) and needs no attack labels.
2. **Gemini is not a reliable classifier of attack families from aggregate flow features.** It was 7–11% correct here. Retrieval of similar known incidents was 62–71% correct, at no API cost.
3. **What fits the evidence is a split of roles:**
   - the detector decides;
   - retrieval names the family and the ATT&CK techniques;
   - Gemini writes the explanation and the response plan from that evidence, and may raise but never lower severity;
   - a human approves.

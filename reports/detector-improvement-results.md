# More reliable detector: before and after

All runs below were scored on the same 800 fresh windows: benchmark seeds 3 and 4, 50 per usable day-file per seed, attack prevalence 0.19. These seeds were never used while choosing the design.

- **Previous**: commit `6f1772f`. Isolation Forest trained on normal traffic, with the TCP-window feature.
- **New**: one-class SVM trained on normal traffic, without the TCP-window shortcut feature. A window is flagged only if the model finds it abnormal and its homogeneity score reaches the original 0.6 gate.

The design was chosen on separate development windows (seed 21) with `scripts/detector_experiment.py`. There, the new detector scored MCC 0.68, the previous one 0.41 and the rules 0.64. The candidates that lost were Local Outlier Factor, robust Mahalanobis distance and a rank ensemble. A variant combining the detector with the full rules reached 0.73, but it brings back the shortcut feature, so it was not adopted.

## Detection (800 windows)

| | MCC [95% CI] | Recall | False alarm rate | Precision | F1 | Accuracy | TP / FP / FN / TN |
|---|---|---|---|---|---|---|---|
| Previous detector | 0.653 [0.61, 0.70] | 0.974 | 19.1% | 0.551 | 0.704 | 0.841 | 151 / 123 / 4 / 522 |
| Rules (reference) | 0.658 [0.60, 0.71] | 0.923 | 15.7% | 0.586 | 0.717 | 0.859 | 143 / 101 / 12 / 544 |
| **New detector** | **0.741** [0.69, 0.79] | **0.974** | **12.4%** | **0.654** | **0.782** | **0.895** | 151 / 80 / 4 / 565 |

The new detector catches every attack the previous one caught and raises 43 fewer false alarms (80 instead of 123).

Paired McNemar tests:

- **Previous vs new:** previous alone right on 10 windows, new alone right on 53 (p < 0.001).
- **Rules vs new:** rules alone right on 26, new alone right on 55 (p = 0.002).

The new detector is now better than the rules, and it does not use the testbed shortcut feature the rules depend on.

## Attack-family naming (149 caught attacks)

| | Exact | Answerable* | Coarse group | Macro-F1 |
|---|---|---|---|---|
| Previous | 50% | 64% | 77% | 0.27 |
| **New** | **57%** | **74%** | 77% | **0.31** |
| Previous + confirmed incidents | 98% | 97% | 100% | 0.98 |
| **New + confirmed incidents** | **98%** | **97%** | **100%** | **0.98** |

\* Botnet and Brute Force excluded. Each exists on one usable day-file only, so no example of them is available when their day is judged.

- **Previous vs new:** the new design is never worse and is better on 11 windows (p = 0.001).
- **With confirmed incidents:** previous and new are identical.

## Combined with the earlier fresh-seed test (seeds 1–2)

| | Seeds 1–2 | Seeds 3–4 |
|---|---|---|
| Attack family, LLM names it (oldest design) | 50% | — |
| Attack family, memory vote | 55% | 57% (previous detector: 50%) |
| Attack family, + confirmed incidents | 97% | 98% |
| Detection MCC, hybrid | 0.64 (Isolation Forest) | **0.74** (new detector) |

Raw files: `reports/final2-*.json`.

To reproduce:

```
python -m aegis.benchmark --mode hybrid --no-llm --seed-start 3 --seeds 2 [--memory]
```

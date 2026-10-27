# Detector tuning: before and after

## What was tried (development windows only, seeds 21 and 22)

All options were tested with `scripts/detector_tuning.py`. Full output is in `reports/detector-tuning-dev.txt`.

| Option | MCC | False alarms | Kept? |
|---|---|---|---|
| Current one-class SVM (budget 5%, nu 0.05, gamma "scale") | 0.702 | 14.3% | baseline |
| Best of 64 budget × nu × gamma combinations | 0.709 | 13.8% | no: within noise |
| Extra behavioural features (payload, inter-arrival time, ACK share) | 0.716 | 14.0% | no: within noise, more complexity |
| **Confirmed-incident memory decides** when analysts have confirmed incidents | **0.764** | **9.7%** | **yes** |

The current settings were already near-optimal, so they stay. The incident memory works like this: a window is called an attack if it is closer to an incident an analyst has already confirmed than to any normal traffic window, and normal otherwise. With no confirmed incidents, the detector behaves exactly as before.

## Confirmation on fresh windows (seeds 5 and 6, used once)

The test used 800 identical windows with attack prevalence 0.185. The comparison is between the previous commit `97f7c9c` and the new code. Confirmed incidents were simulated as attacks from earlier in the same capture, ending at least 5,000 rows before each judged window.

| | MCC [95% CI] | Recall | False alarms | Precision | F1 | Accuracy | TP / FP / FN / TN |
|---|---|---|---|---|---|---|---|
| Previous (with or without confirmed incidents) | 0.740 [0.68, 0.79] | 0.980 | 12.3% | 0.644 | 0.777 | 0.896 | 145 / 80 / 3 / 572 |
| New, no confirmed incidents | 0.740 | 0.980 | 12.3% | 0.644 | 0.777 | 0.896 | identical |
| **New, with confirmed incidents** | **0.784** [0.73, 0.83] | 0.932 | **7.7%** | **0.734** | **0.821** | **0.925** | 138 / 50 / 10 / 602 |

Paired McNemar test, previous vs new with confirmed incidents: previous alone right on 9 windows, new alone right on 32 (p < 0.001).

The trade-off: 30 fewer false alarms for 7 more missed attacks (recall 98% → 93%). The new detector agrees with the previous one exactly whenever no incidents have been confirmed.

## Attack-family naming on the same windows (137 caught attacks)

| | Exact | Answerable | Coarse group |
|---|---|---|---|
| Without confirmed incidents | 56% | 74% | 76% |
| With confirmed incidents | 100% | 100% | 100% |

## All fresh-seed checks so far

| | Seeds 1–2 | Seeds 3–4 | Seeds 5–6 |
|---|---|---|---|
| Detection MCC, no confirmed incidents | 0.64 (Isolation Forest) | 0.74 (one-class SVM) | 0.74 |
| Detection MCC, with confirmed incidents | — | — | **0.78** |
| Attack family, never-seen tools | 55% | 57% | 56% |
| Attack family, with confirmed incidents | 97% | 98% | 100% |

Raw files: `reports/final3-*.json`. To reproduce:

```
python -m aegis.benchmark --mode hybrid --no-llm --seed-start 5 --seeds 2 [--memory]
```

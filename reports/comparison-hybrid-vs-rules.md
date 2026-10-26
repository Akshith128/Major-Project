# Pipeline comparison: rules vs hybrid (same-network, gemini)

400 identical windows (prevalence 0.19).

| Metric | rules | hybrid (same-network, gemini) |
|---|---|---|
| mcc | 0.674 [0.602, 0.748] | 0.564 [0.482, 0.644] |
| balanced_accuracy | 0.889  | 0.841  |
| f1 | 0.729 [0.662, 0.798] | 0.638 [0.557, 0.715] |
| recall | 0.921 [0.838, 0.963] | 0.895 [0.806, 0.946] |
| precision | 0.603 [0.512, 0.688] | 0.496 [0.414, 0.579] |
| false_positive_rate | 0.142 [0.108, 0.184] | 0.213 [0.172, 0.261] |
| accuracy | 0.87 [0.833, 0.899] | 0.807 [0.766, 0.843] |
| TP / FP / FN / TN | 70 / 46 / 6 / 278 | 68 / 69 / 8 / 255 |

Verdicts agree on 329/400 windows. McNemar: only rules right on 48, only hybrid (same-network, gemini) right on 23, p = 0.0041.

## Per day-file (MCC / recall / FPR)

| Day-file | prevalence | rules | hybrid (same-network, gemini) |
|---|---|---|---|
| Botnet-Friday-02-03-2018 | 0.22 | 0.945 / 1.0 / 0.026 | 0.555 / 0.364 / 0.0 |
| Bruteforce-Wednesday-14-02-2018 | 0.16 | 0.676 / 0.5 / 0.0 | 0.822 / 1.0 / 0.071 |
| DDoS1-Tuesday-20-02-2018 | 0.58 | 0.96 / 0.966 / 0.0 | 0.92 / 1.0 / 0.095 |
| DDoS2-Wednesday-21-02-2018 | 0.34 | — / 1.0 / 1.0 | 0.336 / 1.0 / 0.727 |
| DoS1-Thursday-15-02-2018 | 0.06 | 0.808 / 0.667 / 0.0 | 0.383 / 0.667 / 0.106 |
| DoS2-Friday-16-02-2018 | 0.16 | 0.557 / 1.0 / 0.262 | 0.299 / 1.0 / 0.619 |
| Web1-Thursday-22-02-2018 | 0.0 | — / — / 0.0 | — / — / 0.16 |
| Web2-Friday-23-02-2018 | 0.0 | — / — / 0.02 | — / — / 0.02 |

## rules: typing, calibration, governance, cost

- Attack typing: 0/70 correct (0.0); mistakes {'Botnet -> Unknown': 11, 'Brute Force -> Unknown': 4, 'DDoS -> Unknown': 45, 'DoS -> Unknown': 10}.
- Calibration: 0 LLM decisions, ECE —, Brier —, accuracy at confidence ≥80 — vs <80 —.
- Governance: review load 0.29, auto-approved 0 (precision —, 0 benign).
- Cost: 0 LLM calls, fallback rate —, schema failures 0, latency median — ms (p95 —), — tokens/window, model —.

## hybrid (same-network, gemini): typing, calibration, governance, cost

- Attack typing: 20/68 correct (0.294); mistakes {'Botnet -> DDoS': 3, 'Botnet -> DoS': 1, 'Brute Force -> DoS': 8, 'DDoS -> DoS': 14, 'DDoS -> Brute Force': 4, 'DDoS -> Port Scan': 12, 'DDoS -> Botnet': 5, 'DoS -> Botnet': 1}.
- Calibration: 0 LLM decisions, ECE —, Brier —, accuracy at confidence ≥80 — vs <80 —.
- Governance: review load 0.343, auto-approved 0 (precision —, 0 benign).
- Cost: 274 LLM calls, fallback rate 0.0, schema failures 0, latency median 6116 ms (p95 8387.8), 188.8 tokens/window, model gemini-3.5-flash-lite.

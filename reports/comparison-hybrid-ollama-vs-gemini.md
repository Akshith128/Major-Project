# Pipeline comparison: hybrid (same-network, gemini) vs hybrid (same-network, ollama)

400 identical windows (prevalence 0.19).

| Metric | hybrid (same-network, gemini) | hybrid (same-network, ollama) |
|---|---|---|
| mcc | 0.564 [0.482, 0.644] | 0.564 [0.482, 0.644] |
| balanced_accuracy | 0.841  | 0.841  |
| f1 | 0.638 [0.557, 0.715] | 0.638 [0.557, 0.715] |
| recall | 0.895 [0.806, 0.946] | 0.895 [0.806, 0.946] |
| precision | 0.496 [0.414, 0.579] | 0.496 [0.414, 0.579] |
| false_positive_rate | 0.213 [0.172, 0.261] | 0.213 [0.172, 0.261] |
| accuracy | 0.807 [0.766, 0.843] | 0.807 [0.766, 0.843] |
| TP / FP / FN / TN | 68 / 69 / 8 / 255 | 68 / 69 / 8 / 255 |

Verdicts agree on 400/400 windows. McNemar: only hybrid (same-network, gemini) right on 0, only hybrid (same-network, ollama) right on 0, p = 1.0.

## Per day-file (MCC / recall / FPR)

| Day-file | prevalence | hybrid (same-network, gemini) | hybrid (same-network, ollama) |
|---|---|---|---|
| Botnet-Friday-02-03-2018 | 0.22 | 0.555 / 0.364 / 0.0 | 0.555 / 0.364 / 0.0 |
| Bruteforce-Wednesday-14-02-2018 | 0.16 | 0.822 / 1.0 / 0.071 | 0.822 / 1.0 / 0.071 |
| DDoS1-Tuesday-20-02-2018 | 0.58 | 0.92 / 1.0 / 0.095 | 0.92 / 1.0 / 0.095 |
| DDoS2-Wednesday-21-02-2018 | 0.34 | 0.336 / 1.0 / 0.727 | 0.336 / 1.0 / 0.727 |
| DoS1-Thursday-15-02-2018 | 0.06 | 0.383 / 0.667 / 0.106 | 0.383 / 0.667 / 0.106 |
| DoS2-Friday-16-02-2018 | 0.16 | 0.299 / 1.0 / 0.619 | 0.299 / 1.0 / 0.619 |
| Web1-Thursday-22-02-2018 | 0.0 | — / — / 0.16 | — / — / 0.16 |
| Web2-Friday-23-02-2018 | 0.0 | — / — / 0.02 | — / — / 0.02 |

## hybrid (same-network, gemini): typing, calibration, governance, cost

- Attack typing: 20/68 correct (0.294); mistakes {'Botnet -> DDoS': 3, 'Botnet -> DoS': 1, 'Brute Force -> DoS': 8, 'DDoS -> DoS': 14, 'DDoS -> Brute Force': 4, 'DDoS -> Port Scan': 12, 'DDoS -> Botnet': 5, 'DoS -> Botnet': 1}.
- Calibration: 0 LLM decisions, ECE —, Brier —, accuracy at confidence ≥80 — vs <80 —.
- Governance: review load 0.343, auto-approved 0 (precision —, 0 benign).
- Cost: 274 LLM calls, fallback rate 0.0, schema failures 0, latency median 6116 ms (p95 8387.8), 188.8 tokens/window, model gemini-3.5-flash-lite.

## hybrid (same-network, ollama): typing, calibration, governance, cost

- Attack typing: 37/68 correct (0.544); mistakes {'Botnet -> DDoS': 4, 'Brute Force -> DoS': 8, 'DDoS -> DoS': 8, 'DDoS -> Botnet': 5, 'DoS -> Botnet': 1, 'DoS -> DDoS': 5}.
- Calibration: 0 LLM decisions, ECE —, Brier —, accuracy at confidence ≥80 — vs <80 —.
- Governance: review load 0.343, auto-approved 0 (precision —, 0 benign).
- Cost: 274 LLM calls, fallback rate 0.0, schema failures 0, latency median 2068 ms (p95 2739.9), 525.3 tokens/window, model qwen2.5:3b.

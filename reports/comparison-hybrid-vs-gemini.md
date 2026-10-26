# Pipeline comparison: gemini vs hybrid (same-network, gemini)

400 identical windows (prevalence 0.19).

| Metric | gemini | hybrid (same-network, gemini) |
|---|---|---|
| mcc | 0.625 [0.565, 0.688] | 0.564 [0.482, 0.644] |
| balanced_accuracy | 0.886  | 0.841  |
| f1 | 0.673 [0.598, 0.74] | 0.638 [0.557, 0.715] |
| recall | 1.0 [0.952, 1.0] | 0.895 [0.806, 0.946] |
| precision | 0.507 [0.427, 0.586] | 0.496 [0.414, 0.579] |
| false_positive_rate | 0.228 [0.186, 0.277] | 0.213 [0.172, 0.261] |
| accuracy | 0.815 [0.774, 0.85] | 0.807 [0.766, 0.843] |
| TP / FP / FN / TN | 76 / 74 / 0 / 250 | 68 / 69 / 8 / 255 |

Verdicts agree on 319/400 windows. McNemar: only gemini right on 42, only hybrid (same-network, gemini) right on 39, p = 0.8243.

## Per day-file (MCC / recall / FPR)

| Day-file | prevalence | gemini | hybrid (same-network, gemini) |
|---|---|---|---|
| Botnet-Friday-02-03-2018 | 0.22 | 0.811 / 1.0 / 0.103 | 0.555 / 0.364 / 0.0 |
| Bruteforce-Wednesday-14-02-2018 | 0.16 | 0.736 / 1.0 / 0.119 | 0.822 / 1.0 / 0.071 |
| DDoS1-Tuesday-20-02-2018 | 0.58 | 1.0 / 1.0 / 0.0 | 0.92 / 1.0 / 0.095 |
| DDoS2-Wednesday-21-02-2018 | 0.34 | — / 1.0 / 1.0 | 0.336 / 1.0 / 0.727 |
| DoS1-Thursday-15-02-2018 | 0.06 | 0.626 / 1.0 / 0.085 | 0.383 / 0.667 / 0.106 |
| DoS2-Friday-16-02-2018 | 0.16 | 0.436 / 1.0 / 0.405 | 0.299 / 1.0 / 0.619 |
| Web1-Thursday-22-02-2018 | 0.0 | — / — / 0.1 | — / — / 0.16 |
| Web2-Friday-23-02-2018 | 0.0 | — / — / 0.12 | — / — / 0.02 |

## gemini: typing, calibration, governance, cost

- Attack typing: 8/76 correct (0.105); mistakes {'Botnet -> DoS': 11, 'Brute Force -> Botnet': 5, 'DDoS -> DoS': 21, 'DDoS -> Unknown': 2, 'DDoS -> Port Scan': 18, 'DoS -> Botnet': 2, 'DoS -> Brute Force': 1, 'DoS -> DDoS': 1, 'DoS -> Port Scan': 4, 'DoS -> Unknown': 3}.
- Calibration: 144 LLM decisions, ECE 0.351, Brier 0.372, accuracy at confidence ≥80 0.566 vs <80 0.25.
- Governance: review load 0.367, auto-approved 3 (precision 0.667, 1 benign).
- Cost: 327 LLM calls, fallback rate 0.186, schema failures 0, latency median 7588 ms (p95 16917.0), 334.9 tokens/window, model gemini-3.5-flash-lite.

## hybrid (same-network, gemini): typing, calibration, governance, cost

- Attack typing: 20/68 correct (0.294); mistakes {'Botnet -> DDoS': 3, 'Botnet -> DoS': 1, 'Brute Force -> DoS': 8, 'DDoS -> DoS': 14, 'DDoS -> Brute Force': 4, 'DDoS -> Port Scan': 12, 'DDoS -> Botnet': 5, 'DoS -> Botnet': 1}.
- Calibration: 0 LLM decisions, ECE —, Brier —, accuracy at confidence ≥80 — vs <80 —.
- Governance: review load 0.343, auto-approved 0 (precision —, 0 benign).
- Cost: 274 LLM calls, fallback rate 0.0, schema failures 0, latency median 6116 ms (p95 8387.8), 188.8 tokens/window, model gemini-3.5-flash-lite.

# Pipeline comparison: rules vs gemini

400 identical windows (prevalence 0.19).

| Metric | rules | gemini |
|---|---|---|
| mcc | 0.674 [0.602, 0.748] | 0.625 [0.565, 0.688] |
| balanced_accuracy | 0.889  | 0.886  |
| f1 | 0.729 [0.662, 0.798] | 0.673 [0.598, 0.74] |
| recall | 0.921 [0.838, 0.963] | 1.0 [0.952, 1.0] |
| precision | 0.603 [0.512, 0.688] | 0.507 [0.427, 0.586] |
| false_positive_rate | 0.142 [0.108, 0.184] | 0.228 [0.186, 0.277] |
| accuracy | 0.87 [0.833, 0.899] | 0.815 [0.774, 0.85] |
| TP / FP / FN / TN | 70 / 46 / 6 / 278 | 76 / 74 / 0 / 250 |

Verdicts agree on 366/400 windows. McNemar: only rules right on 28, only gemini right on 6, p = 0.0002.

## Per day-file (MCC / recall / FPR)

| Day-file | prevalence | rules | gemini |
|---|---|---|---|
| Botnet-Friday-02-03-2018 | 0.22 | 0.945 / 1.0 / 0.026 | 0.811 / 1.0 / 0.103 |
| Bruteforce-Wednesday-14-02-2018 | 0.16 | 0.676 / 0.5 / 0.0 | 0.736 / 1.0 / 0.119 |
| DDoS1-Tuesday-20-02-2018 | 0.58 | 0.96 / 0.966 / 0.0 | 1.0 / 1.0 / 0.0 |
| DDoS2-Wednesday-21-02-2018 | 0.34 | — / 1.0 / 1.0 | — / 1.0 / 1.0 |
| DoS1-Thursday-15-02-2018 | 0.06 | 0.808 / 0.667 / 0.0 | 0.626 / 1.0 / 0.085 |
| DoS2-Friday-16-02-2018 | 0.16 | 0.557 / 1.0 / 0.262 | 0.436 / 1.0 / 0.405 |
| Web1-Thursday-22-02-2018 | 0.0 | — / — / 0.0 | — / — / 0.1 |
| Web2-Friday-23-02-2018 | 0.0 | — / — / 0.02 | — / — / 0.12 |

## rules: typing, calibration, governance, cost

- Attack typing: 0/70 correct (0.0); mistakes {'Botnet -> Unknown': 11, 'Brute Force -> Unknown': 4, 'DDoS -> Unknown': 45, 'DoS -> Unknown': 10}.
- Calibration: 0 LLM decisions, ECE —, Brier —, accuracy at confidence ≥80 — vs <80 —.
- Governance: review load 0.29, auto-approved 0 (precision —, 0 benign).
- Cost: 0 LLM calls, fallback rate —, schema failures 0, latency median — ms (p95 —), — tokens/window, model —.

## gemini: typing, calibration, governance, cost

- Attack typing: 8/76 correct (0.105); mistakes {'Botnet -> DoS': 11, 'Brute Force -> Botnet': 5, 'DDoS -> DoS': 21, 'DDoS -> Unknown': 2, 'DDoS -> Port Scan': 18, 'DoS -> Botnet': 2, 'DoS -> Brute Force': 1, 'DoS -> DDoS': 1, 'DoS -> Port Scan': 4, 'DoS -> Unknown': 3}.
- Calibration: 144 LLM decisions, ECE 0.351, Brier 0.372, accuracy at confidence ≥80 0.566 vs <80 0.25.
- Governance: review load 0.367, auto-approved 3 (precision 0.667, 1 benign).
- Cost: 327 LLM calls, fallback rate 0.186, schema failures 0, latency median 7588 ms (p95 16917.0), 334.9 tokens/window, model gemini-3.5-flash-lite.

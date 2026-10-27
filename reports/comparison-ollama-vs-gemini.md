# Pipeline comparison: gemini vs ollama

400 identical windows (prevalence 0.19).

| Metric | gemini | ollama |
|---|---|---|
| mcc | 0.625 [0.565, 0.688] | 0.544 [0.484, 0.603] |
| balanced_accuracy | 0.886  | 0.844  |
| f1 | 0.673 [0.598, 0.74] | 0.601 [0.525, 0.669] |
| recall | 1.0 [0.952, 1.0] | 1.0 [0.952, 1.0] |
| precision | 0.507 [0.427, 0.586] | 0.429 [0.359, 0.503] |
| false_positive_rate | 0.228 [0.186, 0.277] | 0.312 [0.264, 0.364] |
| accuracy | 0.815 [0.774, 0.85] | 0.748 [0.703, 0.788] |
| TP / FP / FN / TN | 76 / 74 / 0 / 250 | 76 / 101 / 0 / 223 |

Verdicts agree on 373/400 windows. McNemar: only gemini right on 27, only ollama right on 0, p = 0.0.

## Per day-file (MCC / recall / FPR)

| Day-file | prevalence | gemini | ollama |
|---|---|---|---|
| Botnet-Friday-02-03-2018 | 0.22 | 0.811 / 1.0 / 0.103 | 0.774 / 1.0 / 0.128 |
| Bruteforce-Wednesday-14-02-2018 | 0.16 | 0.736 / 1.0 / 0.119 | 0.736 / 1.0 / 0.119 |
| DDoS1-Tuesday-20-02-2018 | 0.58 | 1.0 / 1.0 / 0.0 | 1.0 / 1.0 / 0.0 |
| DDoS2-Wednesday-21-02-2018 | 0.34 | — / 1.0 / 1.0 | — / 1.0 / 1.0 |
| DoS1-Thursday-15-02-2018 | 0.06 | 0.626 / 1.0 / 0.085 | 0.626 / 1.0 / 0.085 |
| DoS2-Friday-16-02-2018 | 0.16 | 0.436 / 1.0 / 0.405 | — / 1.0 / 1.0 |
| Web1-Thursday-22-02-2018 | 0.0 | — / — / 0.1 | — / — / 0.12 |
| Web2-Friday-23-02-2018 | 0.0 | — / — / 0.12 | — / — / 0.12 |

## gemini: typing, calibration, governance, cost

- Attack typing: 8/76 correct (0.105); mistakes {'Botnet -> DoS': 11, 'Brute Force -> Botnet': 5, 'DDoS -> DoS': 21, 'DDoS -> Unknown': 2, 'DDoS -> Port Scan': 18, 'DoS -> Botnet': 2, 'DoS -> Brute Force': 1, 'DoS -> DDoS': 1, 'DoS -> Port Scan': 4, 'DoS -> Unknown': 3}.
- Calibration: 144 LLM decisions, ECE 0.351, Brier 0.372, accuracy at confidence ≥80 0.566 vs <80 0.25.
- Governance: review load 0.367, auto-approved 3 (precision 0.667, 1 benign).
- Cost: 327 LLM calls, fallback rate 0.186, schema failures 0, latency median 7588 ms (p95 16917.0), 334.9 tokens/window, model gemini-3.5-flash-lite.

## ollama: typing, calibration, governance, cost

- Attack typing: 9/76 correct (0.118); mistakes {'Botnet -> DoS': 6, 'Botnet -> Unknown': 4, 'Brute Force -> Botnet': 6, 'Brute Force -> Unknown': 2, 'DDoS -> Unknown': 9, 'DDoS -> DoS': 37, 'DoS -> Botnet': 3}.
- Calibration: 158 LLM decisions, ECE 0.383, Brier 0.368, accuracy at confidence ≥80 0.556 vs <80 0.302.
- Governance: review load 0.443, auto-approved 0 (precision —, 0 benign).
- Cost: 354 LLM calls, fallback rate 0.107, schema failures 19, latency median 1578 ms (p95 2194.6), 412.8 tokens/window, model qwen2.5:3b.

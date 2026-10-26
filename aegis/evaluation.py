"""Post-run evaluation against ground truth (never visible to the agents).

Beyond accuracy/precision/recall/F1 this reports what small, imbalanced
security test sets need (Chicco & Jurman 2020; Arp et al. 2022):
  * MCC, balanced accuracy, specificity and the attack prevalence of the run;
  * 95% Wilson intervals for the rates, bootstrap intervals for MCC and F1;
  * ROC-AUC / PR-AUC of the continuous monitoring score;
  * classical baselines on the same windows, and McNemar's exact test for
    every pair of detectors (Dietterich 1998);
  * calibration of the LLM's self-reported confidence (ECE, Brier);
  * governance load and operational cost (latency, tokens, fallbacks).
"""

import math
from statistics import median

import numpy as np

BOOTSTRAP = 1000
SEED = 7


def _ratio(a: int, b: int) -> float | None:
    return round(a / b, 3) if b else None


def wilson(k: int, n: int, z: float = 1.96) -> list[float] | None:
    if n == 0:
        return None
    p = k / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return [round(max(0.0, centre - half), 3), round(min(1.0, centre + half), 3)]


def _counts(truth, predicted) -> tuple[int, int, int, int]:
    t, p = np.asarray(truth, bool), np.asarray(predicted, bool)
    return int((t & p).sum()), int((~t & ~p).sum()), int((~t & p).sum()), int((t & ~p).sum())


def _mcc(tp, tn, fp, fn) -> float | None:
    denom = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    return (tp * tn - fp * fn) / denom if denom else None


def _f1(tp, fp, fn) -> float | None:
    return 2 * tp / (2 * tp + fp + fn) if (2 * tp + fp + fn) else None


def _bootstrap(truth, predicted, metric) -> list[float] | None:
    t, p = np.asarray(truth, bool), np.asarray(predicted, bool)
    if len(t) < 5:
        return None
    rng = np.random.default_rng(SEED)
    values = []
    for _ in range(BOOTSTRAP):
        idx = rng.integers(0, len(t), len(t))
        value = metric(*_counts(t[idx], p[idx]))
        if value is not None:
            values.append(value)
    if len(values) < BOOTSTRAP // 2:
        return None
    return [round(float(np.percentile(values, 2.5)), 3), round(float(np.percentile(values, 97.5)), 3)]


def confusion(truth: list[bool], predicted: list[bool]) -> dict:
    tp, tn, fp, fn = _counts(truth, predicted)
    n = len(truth)
    precision, recall = _ratio(tp, tp + fp), _ratio(tp, tp + fn)
    specificity = _ratio(tn, tn + fp)
    f1 = _f1(tp, fp, fn)
    mcc = _mcc(tp, tn, fp, fn)
    return {
        "n": n,
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "prevalence": _ratio(tp + fn, n),
        "accuracy": _ratio(tp + tn, n),
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "f1": round(f1, 3) if precision is not None and recall is not None else None,
        "false_positive_rate": _ratio(fp, fp + tn),
        "balanced_accuracy": round((recall + specificity) / 2, 3) if recall is not None and specificity is not None else None,
        "mcc": round(mcc, 3) if mcc is not None else None,
        "ci95": {
            "accuracy": wilson(tp + tn, n),
            "precision": wilson(tp, tp + fp),
            "recall": wilson(tp, tp + fn),
            "false_positive_rate": wilson(fp, fp + tn),
            "f1": _bootstrap(truth, predicted, lambda tp, tn, fp, fn: _f1(tp, fp, fn)),
            "mcc": _bootstrap(truth, predicted, _mcc),
        },
    }


def mcnemar(truth: list[bool], a: list[bool], b: list[bool]) -> dict:
    """Exact McNemar test on the windows where exactly one detector is right."""
    from scipy.stats import binomtest

    a_only = sum((x == t) and (y != t) for t, x, y in zip(truth, a, b))
    b_only = sum((y == t) and (x != t) for t, x, y in zip(truth, a, b))
    discordant = a_only + b_only
    p = binomtest(a_only, discordant, 0.5).pvalue if discordant else 1.0
    return {"a_only_correct": a_only, "b_only_correct": b_only, "p_value": round(float(p), 4)}


def score_auc(truth: list[bool], scores: list[float]) -> dict:
    if len(set(truth)) < 2:
        return {"roc_auc": None, "pr_auc": None, "note": "Needs both attack and benign windows."}
    from sklearn.metrics import average_precision_score, roc_auc_score

    return {
        "roc_auc": round(float(roc_auc_score(truth, scores)), 3),
        "pr_auc": round(float(average_precision_score(truth, scores)), 3),
    }


def calibration(windows: list[dict], bins: int = 5) -> dict:
    """Does the LLM's stated confidence match how often its verdict is right?"""
    rows = [
        (w["detection"]["confidence"] / 100, w["detection"]["threat"] == w["truth"]["is_attack"])
        for w in windows
        if w.get("detection", {}).get("source") == "gemini"
    ]
    if not rows:
        return {"n": 0, "note": "No Gemini decisions in this set."}
    conf = np.array([c for c, _ in rows])
    correct = np.array([k for _, k in rows], float)
    edges = np.linspace(0, 1, bins + 1)
    ece, table = 0.0, []
    for lo, hi in zip(edges[:-1], edges[1:]):
        mask = (conf > lo) & (conf <= hi) if lo > 0 else (conf >= lo) & (conf <= hi)
        if mask.any():
            gap = abs(conf[mask].mean() - correct[mask].mean())
            ece += mask.mean() * gap
            table.append({"bin": [round(lo, 2), round(hi, 2)], "n": int(mask.sum()),
                          "mean_confidence": round(float(conf[mask].mean()), 3),
                          "accuracy": round(float(correct[mask].mean()), 3)})
    high = conf >= 0.8
    return {
        "n": len(rows),
        "ece": round(float(ece), 3),
        "brier": round(float(((conf - correct) ** 2).mean()), 3),
        "accuracy_conf_ge_80": round(float(correct[high].mean()), 3) if high.any() else None,
        "accuracy_conf_lt_80": round(float(correct[~high].mean()), 3) if (~high).any() else None,
        "bins": table,
    }


def governance_metrics(windows: list[dict]) -> dict:
    threats = [w for w in windows if w.get("detection", {}).get("threat")]
    auto = [w for w in threats if w["governance"]["decision"] == "AUTO_APPROVED"]
    pending = [w for w in threats if w["governance"]["decision"] == "PENDING_REVIEW"]
    reviewed = [w for w in pending if w.get("review")]
    rejected = [w for w in reviewed if w["review"]["decision"] == "REJECTED"]
    attacks = [w for w in windows if w["truth"]["is_attack"]]
    return {
        "responses": len(threats),
        "review_load": _ratio(len(pending), len(windows)),
        "auto_approved": len(auto),
        "auto_approval_precision": _ratio(sum(w["truth"]["is_attack"] for w in auto), len(auto)),
        "auto_approved_benign": sum(not w["truth"]["is_attack"] for w in auto),
        "escalation_recall": _ratio(sum(w["truth"]["is_attack"] for w in pending), len(attacks)),
        "reviewed": len(reviewed),
        "override_rate": _ratio(len(rejected), len(reviewed)),
    }


def _p95(values: list[float]) -> float | None:
    return round(float(np.percentile(values, 95)), 1) if values else None


def operations(windows: list[dict]) -> dict:
    calls = [w[a]["provenance"] for w in windows for a in ("detection", "response") if "provenance" in w.get(a, {})]
    latency = [c["latency_ms"] for c in calls if c.get("latency_ms") is not None and c.get("schema_valid")]
    tokens = [(c.get("tokens_in") or 0) + (c.get("tokens_out") or 0) for c in calls]
    detections = [w["detection"] for w in windows if "detection" in w]
    fallbacks = sum(d["source"] == "rules" for d in detections)
    return {
        "llm_calls": len(calls),
        "escalation_rate": _ratio(len(detections), len(windows)),
        "detection_fallback_rate": _ratio(fallbacks, len(detections)) if calls else None,
        "schema_invalid": sum(c.get("schema_valid") is False for c in calls),
        "latency_ms_median": round(median(latency)) if latency else None,
        "latency_ms_p95": _p95(latency),
        "tokens_total": sum(tokens) if calls else None,
        "tokens_per_window": round(sum(tokens) / len(windows), 1) if calls and windows else None,
        "model_versions": sorted({c["model_version"] for c in calls if c.get("model_version")}),
    }


def evaluate(windows: list[dict]) -> dict:
    truth = [w["truth"]["is_attack"] for w in windows]
    detectors = {
        "monitoring": [w["monitoring"]["suspicious"] for w in windows],
        "pipeline": [bool(w.get("detection", {}).get("threat")) for w in windows],
    }
    for name in ("random_forest", "tcp_window_rule"):
        verdicts = [w.get("baselines", {}).get(name) for w in windows]
        if verdicts and all(v is not None for v in verdicts):
            detectors[name] = [v["attack"] for v in verdicts]

    names = list(detectors)
    return {
        **{name: confusion(truth, detectors[name]) for name in ("monitoring", "pipeline")},
        "baselines": {name: confusion(truth, detectors[name]) for name in names if name not in ("monitoring", "pipeline")},
        "comparisons": [
            {"a": a, "b": b, **mcnemar(truth, detectors[a], detectors[b])}
            for i, a in enumerate(names)
            for b in names[i + 1 :]
        ],
        "monitoring_auc": score_auc(truth, [w["monitoring"]["score"] for w in windows]),
        "calibration": calibration(windows),
        "governance": governance_metrics(windows),
        "operations": operations(windows),
    }

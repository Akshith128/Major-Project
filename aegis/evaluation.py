"""Post-run evaluation against ground truth (never visible to the agents)."""


def confusion(truth: list[bool], predicted: list[bool]) -> dict:
    tp = sum(t and p for t, p in zip(truth, predicted))
    tn = sum(not t and not p for t, p in zip(truth, predicted))
    fp = sum(not t and p for t, p in zip(truth, predicted))
    fn = sum(t and not p for t, p in zip(truth, predicted))

    def ratio(a: int, b: int) -> float | None:
        return round(a / b, 3) if b else None

    precision, recall = ratio(tp, tp + fp), ratio(tp, tp + fn)
    if precision is None or recall is None:
        f1 = None
    elif precision + recall == 0:
        f1 = 0.0
    else:
        f1 = round(2 * precision * recall / (precision + recall), 3)
    return {
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "accuracy": ratio(tp + tn, len(truth)),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": ratio(fp, fp + tn),
    }


def evaluate(windows: list[dict]) -> dict:
    truth = [w["truth"]["is_attack"] for w in windows]
    return {
        "monitoring": confusion(truth, [w["monitoring"]["suspicious"] for w in windows]),
        "pipeline": confusion(truth, [bool(w.get("detection", {}).get("threat")) for w in windows]),
    }

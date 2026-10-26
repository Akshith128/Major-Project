"""Compare two benchmark runs over the same windows (e.g. Gemini vs rules).

    python scripts/compare_benchmarks.py reports/benchmark-rules-seed0.json reports/benchmark-gemini-seed0.json

Windows are paired by day-file, seed and row, so the McNemar test compares the
two pipelines on exactly the same traffic.
"""

import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegis.evaluation import confusion, mcnemar  # noqa: E402


def load(path: str) -> tuple[dict, dict]:
    report = json.loads(Path(path).read_text(encoding="utf-8"))
    windows = {(w["dataset"], w["seed"], w["row_start"]): w for w in report["window_results"] if w["repeat"] == 0}
    return report, windows


def label(report: dict) -> str:
    s = report["settings"]
    if s["mode"] == "hybrid":
        return f"hybrid ({s.get('baseline', 'same-network')}, {s['provider']})"
    return s["provider"]


def fmt(value) -> str:
    return "—" if value is None else str(value)


def main() -> None:
    (rep_a, a), (rep_b, b) = load(sys.argv[1]), load(sys.argv[2])
    name_a, name_b = label(rep_a), label(rep_b)
    keys = sorted(set(a) & set(b))
    truth = [a[k]["is_attack"] for k in keys]
    pa = [a[k]["verdicts"]["pipeline"] for k in keys]
    pb = [b[k]["verdicts"]["pipeline"] for k in keys]
    ma, mb = confusion(truth, pa), confusion(truth, pb)
    test = mcnemar(truth, pa, pb)
    agree = sum(x == y for x, y in zip(pa, pb))

    lines = [
        f"# Pipeline comparison: {name_a} vs {name_b}",
        "",
        f"{len(keys)} identical windows (prevalence {ma['prevalence']}).",
        "",
        f"| Metric | {name_a} | {name_b} |",
        "|---|---|---|",
    ]
    for key in ("mcc", "balanced_accuracy", "f1", "recall", "precision", "false_positive_rate", "accuracy"):
        ci_a, ci_b = ma["ci95"].get(key), mb["ci95"].get(key)
        lines.append(
            f"| {key} | {fmt(ma[key])} {fmt(ci_a) if ci_a else ''} | {fmt(mb[key])} {fmt(ci_b) if ci_b else ''} |"
        )
    lines += [
        f"| TP / FP / FN / TN | {ma['tp']} / {ma['fp']} / {ma['fn']} / {ma['tn']} | {mb['tp']} / {mb['fp']} / {mb['fn']} / {mb['tn']} |",
        "",
        f"Verdicts agree on {agree}/{len(keys)} windows. McNemar: only {name_a} right on "
        f"{test['a_only_correct']}, only {name_b} right on {test['b_only_correct']}, p = {test['p_value']}.",
        "",
        f"## Per day-file (MCC / recall / FPR)",
        "",
        f"| Day-file | prevalence | {name_a} | {name_b} |",
        "|---|---|---|---|",
    ]
    by_day = defaultdict(list)
    for k in keys:
        by_day[k[0]].append(k)
    for day, ks in sorted(by_day.items()):
        t = [a[k]["is_attack"] for k in ks]
        da = confusion(t, [a[k]["verdicts"]["pipeline"] for k in ks])
        db = confusion(t, [b[k]["verdicts"]["pipeline"] for k in ks])
        lines.append(
            f"| {day.split('_')[0]} | {da['prevalence']} | "
            f"{fmt(da['mcc'])} / {fmt(da['recall'])} / {fmt(da['false_positive_rate'])} | "
            f"{fmt(db['mcc'])} / {fmt(db['recall'])} / {fmt(db['false_positive_rate'])} |"
        )

    for title, rep in ((name_a, rep_a), (name_b, rep_b)):
        p = rep["pooled"]
        typing, cal, ops, gov = p.get("attack_typing", {}), p["calibration"], p["operations"], p["governance"]
        lines += [
            "",
            f"## {title}: typing, calibration, governance, cost",
            "",
            f"- Attack typing: {typing.get('correct', 0)}/{typing.get('n', 0)} correct ({fmt(typing.get('accuracy'))}); "
            f"mistakes {typing.get('confusions') or 'none'}.",
            f"- Calibration: {cal.get('n', 0)} LLM decisions, ECE {fmt(cal.get('ece'))}, Brier {fmt(cal.get('brier'))}, "
            f"accuracy at confidence ≥80 {fmt(cal.get('accuracy_conf_ge_80'))} vs <80 {fmt(cal.get('accuracy_conf_lt_80'))}.",
            f"- Governance: review load {fmt(gov['review_load'])}, auto-approved {gov['auto_approved']} "
            f"(precision {fmt(gov['auto_approval_precision'])}, {gov['auto_approved_benign']} benign).",
            f"- Cost: {ops['llm_calls']} LLM calls, fallback rate {fmt(ops['detection_fallback_rate'])}, "
            f"schema failures {ops['schema_invalid']}, latency median {fmt(ops['latency_ms_median'])} ms "
            f"(p95 {fmt(ops['latency_ms_p95'])}), {fmt(ops['tokens_per_window'])} tokens/window, "
            f"model {', '.join(ops['model_versions']) or '—'}.",
        ]
    text = "\n".join(lines) + "\n"
    out = Path(sys.argv[3]) if len(sys.argv) > 3 else None
    if out:
        out.write_text(text, encoding="utf-8")
    sys.stdout.reconfigure(errors="replace")
    print(text)


if __name__ == "__main__":
    main()

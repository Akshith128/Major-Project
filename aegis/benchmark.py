"""Multi-day benchmark: the evaluation a single 10-window run cannot give.

    python -m aegis.benchmark                              # rules mode, 50 windows x every usable day-file x 3 seeds
    python -m aegis.benchmark --mode llm --seeds 1 --repeats 3      # LLM variance on identical windows
    python -m aegis.benchmark --ablate-tcp-window          # does detection lean on the TCP-window shortcut?
    python -m aegis.benchmark --label-threshold 0.1        # sensitivity to the window-labelling rule

For every seed it samples windows from each day-file (Infiltration days are
left out unless --include-infiltration), scores the Random Forest baseline
trained on the *other* day-files, and runs the agents. It then reports, for the
monitoring gate, the full pipeline and both baselines:
  * pooled metrics with 95% CIs, McNemar tests, ROC/PR-AUC, calibration, cost;
  * mean ± SD across seeds (sampling variance);
  * per day-file and per attack label results;
  * the verdict flip rate across repeats (LLM non-determinism).

Results go to reports/benchmark-<time>.json and .md. No audit trail is written.
"""

import argparse
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from statistics import mean, stdev

from . import anomaly, config, data
from .evaluation import confusion, dominant_attack_label, evaluate
from .graph import build_graph
from .llm import NoLLM, make_llm
from .runs import analyse_window, baseline_verdicts

DETECTORS = {
    "monitoring": lambda w: w["monitoring"]["suspicious"],
    "pipeline": lambda w: bool(w.get("detection", {}).get("threat")),
    "random_forest": lambda w: (w.get("baselines") or {}).get("random_forest", {}).get("attack"),
    "tcp_window_rule": lambda w: (w.get("baselines") or {}).get("tcp_window_rule", {}).get("attack"),
}
HEADLINE = ("mcc", "balanced_accuracy", "f1", "recall", "false_positive_rate")


def _verdicts(windows: list[dict]) -> dict:
    out = {}
    for name, get in DETECTORS.items():
        values = [get(w) for w in windows]
        if all(v is not None for v in values):
            out[name] = values
    return out


def run(args) -> dict:
    if args.mode == "gemini":
        args.mode = "llm"
    llm = NoLLM() if args.mode == "rules" or args.no_llm else make_llm(args.provider)
    if args.mode == "llm" and not llm.configured:
        raise SystemExit(f"LLM mode needs a working reasoning model: {llm.note}")
    if not llm.configured:
        llm = NoLLM()
    graph = build_graph(llm)
    detector_info = {}

    datasets = [
        d for d in data.list_datasets()
        if (args.include_infiltration or not d["excluded_by_default"])
        and (not args.datasets or any(d["dataset_id"].startswith(p) for p in args.datasets))
    ]
    if not datasets:
        raise SystemExit("No day-files to benchmark in data/raw/.")

    results = []  # every analysed window, tagged with dataset / seed / repeat
    for seed in range(args.seeds):
        for d in datasets:
            loaded = data.load_windows(
                d["dataset_id"], args.windows_per_file, args.window_size, "spread",
                seed=seed, label_threshold=args.label_threshold,
                ablate_tcp_window=args.ablate_tcp_window, include_flows=True,
            )
            per_window, _ = baseline_verdicts(d["dataset_id"], loaded, args.label_threshold, args.ablate_tcp_window)
            if args.mode == "hybrid":
                evidence, detector_info[d["dataset_id"]] = anomaly.score(
                    d["dataset_id"], loaded, args.window_size, args.baseline, args.ablate_tcp_window
                )
                for w, ev in zip(loaded, evidence):
                    w["detector"] = ev
            for w in loaded:
                w.pop("flows")
            for repeat in range(args.repeats):
                prior: Counter = Counter()
                for w, baseline in zip(loaded, per_window):
                    result = analyse_window(graph, w, prior, baseline)
                    result.update(dataset=d["dataset_id"], seed=seed, repeat=repeat)
                    results.append(result)
            print(f"seed {seed}  {d['dataset_id'][:32]:<34} done")

    first = [r for r in results if r["repeat"] == 0]
    report = {
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "settings": {
            **{k: v for k, v in vars(args).items() if k != "out"},
            "provider": llm.provider,
            "model": llm.model,
            "datasets": [d["dataset_id"] for d in datasets],
            "monitoring_threshold": config.MONITORING_THRESHOLD,
        },
        "windows": len(first),
        "pooled": evaluate(first),
        "detector": detector_info or None,
    }

    # Sampling variance: one evaluation per seed.
    per_seed = defaultdict(lambda: defaultdict(list))
    for seed in range(args.seeds):
        windows = [r for r in first if r["seed"] == seed]
        truth = [w["truth"]["is_attack"] for w in windows]
        for name, verdicts in _verdicts(windows).items():
            m = confusion(truth, verdicts)
            for key in HEADLINE:
                if m[key] is not None:
                    per_seed[name][key].append(m[key])
    report["across_seeds"] = {
        name: {
            key: {"mean": round(mean(v), 3), "sd": round(stdev(v), 3) if len(v) > 1 else None, "runs": len(v)}
            for key, v in metrics.items()
        }
        for name, metrics in per_seed.items()
    }

    # Where do errors cluster?
    report["per_dataset"] = {}
    for d in datasets:
        windows = [r for r in first if r["dataset"] == d["dataset_id"]]
        truth = [w["truth"]["is_attack"] for w in windows]
        report["per_dataset"][d["dataset_id"]] = {
            name: {k: confusion(truth, v)[k] for k in ("n", "prevalence", "mcc", "recall", "false_positive_rate")}
            for name, v in _verdicts(windows).items()
        }
    by_label = defaultdict(list)
    for w in first:
        if w["truth"]["is_attack"]:
            attack_labels = {k: v for k, v in w["truth"]["label_counts"].items() if k != "Benign"}
            by_label[max(attack_labels, key=attack_labels.get)].append(w)
    report["recall_by_attack_label"] = {
        label: {"windows": len(ws), **{name: round(sum(v) / len(v), 3) for name, v in _verdicts(ws).items()}}
        for label, ws in sorted(by_label.items())
    }

    # Per-window verdicts, so two benchmarks over the same windows can be paired.
    report["window_results"] = [
        {
            "dataset": r["dataset"],
            "seed": r["seed"],
            "repeat": r["repeat"],
            "index": r["index"],
            "row_start": r["row_start"],
            "is_attack": r["truth"]["is_attack"],
            "attack_label": dominant_attack_label(r),
            "score": r["monitoring"]["score"],
            "verdicts": {name: get(r) for name, get in DETECTORS.items()},
            "attack_type": r.get("detection", {}).get("attack_type"),
            "confidence": r.get("detection", {}).get("confidence"),
            "source": r.get("detection", {}).get("source"),
            "decision": r["governance"]["decision"],
        }
        for r in results
    ]

    # LLM non-determinism: same windows, repeated.
    if args.repeats > 1:
        groups = defaultdict(set)
        for r in results:
            groups[(r["dataset"], r["seed"], r["index"])].add(bool(r.get("detection", {}).get("threat")))
        flips = sum(len(v) > 1 for v in groups.values())
        report["repeat_flip_rate"] = round(flips / len(groups), 3)
    return report


def _fmt(value) -> str:
    if value is None:
        return "—"
    if isinstance(value, list):
        return f"[{value[0]}, {value[1]}]"
    return str(value)


def markdown(report: dict) -> str:
    s, pooled = report["settings"], report["pooled"]
    rows = {"monitoring": pooled["monitoring"], "pipeline": pooled["pipeline"], **pooled["baselines"]}
    lines = [
        "# AEGIS benchmark",
        "",
        f"{report['windows']} windows ({s['windows_per_file']} per day-file × {len(s['datasets'])} day-files × "
        f"{s['seeds']} seeds), {s['window_size']} flows each, mode: {s['mode']}"
        f"{' (' + s['baseline'] + ' baseline)' if s['mode'] == 'hybrid' else ''}, reasoning: {s['provider']}"
        f"{' ' + s['model'] if s['model'] else ''}. Label threshold {s['label_threshold']}"
        f"{', TCP-window feature removed' if s['ablate_tcp_window'] else ''}. "
        f"Attack prevalence {pooled['pipeline']['prevalence']}.",
        "",
        "## Pooled results (95% CI)",
        "",
        "| Detector | MCC | Balanced acc. | F1 | Recall | FPR | Accuracy |",
        "|---|---|---|---|---|---|---|",
    ]
    for name, m in rows.items():
        ci = m["ci95"]
        lines.append(
            f"| {name} | {_fmt(m['mcc'])} {_fmt(ci['mcc'])} | {_fmt(m['balanced_accuracy'])} | "
            f"{_fmt(m['f1'])} {_fmt(ci['f1'])} | {_fmt(m['recall'])} {_fmt(ci['recall'])} | "
            f"{_fmt(m['false_positive_rate'])} {_fmt(ci['false_positive_rate'])} | {_fmt(m['accuracy'])} {_fmt(ci['accuracy'])} |"
        )
    lines += ["", "## Paired comparisons (McNemar, exact)", "", "| A | B | only A right | only B right | p |", "|---|---|---|---|---|"]
    for c in pooled["comparisons"]:
        lines.append(f"| {c['a']} | {c['b']} | {c['a_only_correct']} | {c['b_only_correct']} | {c['p_value']} |")
    lines += ["", "## Across seeds (mean ± SD)", "", "| Detector | " + " | ".join(HEADLINE) + " |", "|---|" + "---|" * len(HEADLINE)]
    for name, metrics in report["across_seeds"].items():
        cells = [f"{metrics[k]['mean']} ± {_fmt(metrics[k]['sd'])}" if k in metrics else "—" for k in HEADLINE]
        lines.append(f"| {name} | " + " | ".join(cells) + " |")
    lines += ["", "## Per day-file (MCC / recall / FPR)", "", "| Day-file | prevalence | " + " | ".join(rows) + " |", "|---|---|" + "---|" * len(rows)]
    for dataset_id, detectors in report["per_dataset"].items():
        prevalence = next(iter(detectors.values()))["prevalence"] if detectors else None
        cells = [
            f"{_fmt(detectors[n]['mcc'])} / {_fmt(detectors[n]['recall'])} / {_fmt(detectors[n]['false_positive_rate'])}"
            if n in detectors else "—"
            for n in rows
        ]
        lines.append(f"| {dataset_id.split('_')[0]} | {_fmt(prevalence)} | " + " | ".join(cells) + " |")
    lines += ["", "## Recall by attack label", "", "| Label | windows | " + " | ".join(rows) + " |", "|---|---|" + "---|" * len(rows)]
    for label, r in report["recall_by_attack_label"].items():
        lines.append(f"| {label} | {r['windows']} | " + " | ".join(_fmt(r.get(n)) for n in rows) + " |")
    auc, cal, ops, gov = pooled["monitoring_auc"], pooled["calibration"], pooled["operations"], pooled["governance"]
    typing = pooled["attack_typing"]
    lines += [
        "",
        "## Monitoring score, calibration, governance and cost",
        "",
        f"- Monitoring score ROC-AUC {_fmt(auc.get('roc_auc'))}, PR-AUC {_fmt(auc.get('pr_auc'))}.",
        f"- LLM confidence calibration: {cal.get('n', 0)} LLM decisions, ECE {_fmt(cal.get('ece'))}, Brier {_fmt(cal.get('brier'))}; "
        f"accuracy at confidence ≥80: {_fmt(cal.get('accuracy_conf_ge_80'))}, below 80: {_fmt(cal.get('accuracy_conf_lt_80'))}.",
        f"- Attack typing: {typing.get('correct', 0)}/{typing.get('n', 0)} caught attacks named correctly "
        f"({_fmt(typing.get('accuracy'))}); mistakes: {typing.get('confusions') or 'none'}.",
        f"- Governance: review load {_fmt(gov['review_load'])}, auto-approval precision {_fmt(gov['auto_approval_precision'])} "
        f"({gov['auto_approved_benign']} benign windows auto-approved), escalation recall {_fmt(gov['escalation_recall'])}.",
        f"- Cost: {ops['llm_calls']} LLM calls, escalation rate {_fmt(ops['escalation_rate'])}, fallback rate {_fmt(ops['detection_fallback_rate'])}, "
        f"latency median {_fmt(ops['latency_ms_median'])} ms / p95 {_fmt(ops['latency_ms_p95'])} ms, tokens per window {_fmt(ops['tokens_per_window'])}.",
    ]
    if "repeat_flip_rate" in report:
        lines.append(f"- Pipeline verdict flipped across {s['repeats']} repeats on {report['repeat_flip_rate']} of windows.")
    lines += [
        "",
        "Caveats: original CSE-CIC-IDS2018 labels contain documented errors (see data.DATASET_NOTES); "
        "windows follow CSV row order because the files carry no timestamps.",
    ]
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m aegis.benchmark", description=__doc__.split("\n\n")[0])
    parser.add_argument("--windows-per-file", type=int, default=50)
    parser.add_argument("--window-size", type=int, default=100)
    parser.add_argument("--seeds", type=int, default=3)
    parser.add_argument("--repeats", type=int, default=1, help="LLM repeats on identical windows")
    parser.add_argument("--mode", choices=["auto", "llm", "gemini", "rules", "hybrid"], default="rules")
    parser.add_argument("--provider", choices=["ollama", "groq", "gemini"], default=None,
                        help="reasoning model (default: AEGIS_LLM_PROVIDER)")
    parser.add_argument("--baseline", choices=list(anomaly.BASELINES), default="same-network",
                        help="hybrid: how the anomaly detector learns normal traffic")
    parser.add_argument("--no-llm", action="store_true", help="hybrid without a reasoning model (detector-only)")
    parser.add_argument("--label-threshold", type=float, default=0.5)
    parser.add_argument("--ablate-tcp-window", action="store_true")
    parser.add_argument("--include-infiltration", action="store_true")
    parser.add_argument("--datasets", nargs="*", help="day-file name prefixes, e.g. DDoS1 Botnet")
    parser.add_argument("--out", default=None, help="output path without extension")
    args = parser.parse_args()

    report = run(args)
    out = args.out or str(config.ROOT / "reports" / f"benchmark-{datetime.now():%Y%m%d-%H%M%S}")
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out + ".json").write_text(json.dumps(report, indent=1), encoding="utf-8")
    Path(out + ".md").write_text(markdown(report), encoding="utf-8")
    sys.stdout.reconfigure(errors="replace")  # Windows consoles may not encode ≥ or ±
    print(markdown(report))
    print(f"Saved {out}.json and {out}.md")


if __name__ == "__main__":
    main()

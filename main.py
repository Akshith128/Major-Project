"""Run the AEGIS agent pipeline from the command line.

    python main.py                                  # first dataset, 10 windows
    python main.py --dataset DDoS1-Tuesday-20-02-2018_TrafficForML_CICFlowMeter.parquet --mode rules
"""

import argparse

from aegis import PROJECT_SUBTITLE, PROJECT_TITLE, data
from aegis.runs import RunService


def main() -> None:
    datasets = [d["dataset_id"] for d in data.list_datasets()]
    parser = argparse.ArgumentParser(description=PROJECT_TITLE)
    parser.add_argument("--dataset", default=datasets[0] if datasets else None, choices=datasets or None)
    parser.add_argument("--windows", type=int, default=10)
    parser.add_argument("--window-size", type=int, default=100)
    parser.add_argument("--sampling", choices=["spread", "sequential"], default="spread")
    parser.add_argument("--start-row", type=int, default=0)
    parser.add_argument("--mode", choices=["auto", "gemini", "rules"], default="auto")
    parser.add_argument("--operator", default="CLI")
    parser.add_argument("--seed", type=int, default=None, help="jitter spread windows for repeat runs")
    args = parser.parse_args()
    if not args.dataset:
        parser.error("No datasets found in data/raw/.")

    print(f"AEGIS — {PROJECT_TITLE}\n{PROJECT_SUBTITLE}\n")
    run = RunService().start(
        args.dataset,
        args.windows,
        args.window_size,
        args.sampling,
        args.start_row,
        args.mode,
        {"username": "cli", "name": args.operator, "role": "analyst"},
        background=False,
        seed=args.seed,
    )
    print(f"Run {run['id']} · {run['status']} · reasoning: {run['llm']['provider']}")
    for w in run["windows"]:
        d = w.get("detection") or {}
        print(
            f"  W{w['index']:>3}  score {w['monitoring']['score']:.2f}  "
            f"{'THREAT ' + str(d.get('attack_type')) if d.get('threat') else 'clear':<20} "
            f"{w.get('risk', {}).get('severity', ''):<9} {w['governance']['decision']:<15} "
            f"truth: {w['truth']['dominant_label']}"
        )
    if run["error"]:
        print("Error:", run["error"])
    if run["evaluation"]:
        ev = run["evaluation"]
        rows = {"monitoring": ev["monitoring"], "pipeline": ev["pipeline"], **ev["baselines"]}
        print(f"
Attack prevalence {ev['pipeline']['prevalence']} over {ev['pipeline']['n']} windows")
        for layer, m in rows.items():
            print(
                f"{layer:>16}: MCC {m['mcc']}  balanced acc {m['balanced_accuracy']}  "
                f"precision {m['precision']}  recall {m['recall']}  f1 {m['f1']}  (accuracy 95% CI {m['ci95']['accuracy']})"
            )
        for c in ev["comparisons"]:
            print(f"  McNemar {c['a']} vs {c['b']}: p = {c['p_value']}")
        print("For hundreds of windows across day-files use: python -m aegis.benchmark")


if __name__ == "__main__":
    main()

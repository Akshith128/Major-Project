"""Score attack-family naming from benchmark JSON files, paired window by window.

    python scripts/typing_report.py --seeds 1 2 old=reports/final-old-design.json new=reports/final-new-novel.json memory=reports/final-new-memory.json

Only true attacks that the pipeline caught are scored. Families that do not
appear in the other day-files (Botnet, Brute Force with leave-day-out
training) are reported separately, since no example of them exists when their
day is judged.
"""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegis.evaluation import expected_attack_type, mcnemar, wilson  # noqa: E402
from aegis.family import GROUPS  # noqa: E402

UNSEEN = {"Botnet", "Brute Force"}  # each on one usable day-file only


def caught(path: str, seeds: set[int]) -> dict:
    report = json.loads(Path(path).read_text(encoding="utf-8"))
    out = {}
    for w in report["window_results"]:
        if w["repeat"] == 0 and w["seed"] in seeds and w["is_attack"] and w["verdicts"]["pipeline"]:
            out[(w["dataset"], w["seed"], w["row_start"])] = (expected_attack_type(w["attack_label"]), w["attack_type"])
    return out


def macro_f1(pairs) -> float:
    families = sorted({t for t, _ in pairs})
    scores = []
    for f in families:
        tp = sum(t == f and p == f for t, p in pairs)
        fp = sum(t != f and p == f for t, p in pairs)
        fn = sum(t == f and p != f for t, p in pairs)
        scores.append(2 * tp / (2 * tp + fp + fn) if tp else 0.0)
    return sum(scores) / len(scores)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seeds", type=int, nargs="+", required=True)
    parser.add_argument("runs", nargs="+", help="name=path.json")
    args = parser.parse_args()
    seeds = set(args.seeds)
    runs = {name: caught(path, seeds) for name, path in (r.split("=", 1) for r in args.runs)}
    keys = sorted(set.intersection(*(set(r) for r in runs.values())))
    truth = [next(iter(runs.values()))[k][0] for k in keys]
    print(f"{len(keys)} caught attack windows present in every run (seeds {sorted(seeds)}): {dict(Counter(truth))}\n")
    print(f"{'design':<10}{'exact':>16}{'answerable':>16}{'coarse group':>16}{'macro-F1':>10}")
    correct = {}
    for name, r in runs.items():
        pairs = [r[k] for k in keys]
        ok = [t == p for t, p in pairs]
        correct[name] = ok
        answerable = [t == p for t, p in pairs if t not in UNSEEN]
        group = [GROUPS.get(t) == GROUPS.get(p) for t, p in pairs]

        def cell(xs):
            k, n = sum(xs), len(xs)
            lo, hi = wilson(k, n) or (0, 0)
            return f"{k / n:.2f} [{lo:.2f},{hi:.2f}]" if n else "—"

        print(f"{name:<10}{cell(ok):>16}{cell(answerable):>16}{cell(group):>16}{macro_f1(pairs):>10.3f}")
        print(f"          mistakes: {dict(Counter(f'{t}->{p}' for t, p in pairs if t != p).most_common(6))}")
    names = list(runs)
    print()
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            m = mcnemar([True] * len(keys), correct[a], correct[b])
            print(f"McNemar {a} vs {b}: only {a} right {m['a_only_correct']}, only {b} right {m['b_only_correct']}, p = {m['p_value']}")


if __name__ == "__main__":
    main()

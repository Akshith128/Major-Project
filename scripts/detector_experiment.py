"""Development experiment: which detector separates attack from normal windows best?

    python scripts/detector_experiment.py

For every usable day-file, windows are drawn with development seed 21 (never
a benchmark seed). Each detector learns normal traffic the same way as the
production one (same-network normal windows that do not overlap the judged
windows) and is scored by MCC over all days pooled. Nothing here uses attack
labels for training except where noted (the rules use fixed thresholds).
"""

import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegis import anomaly, data  # noqa: E402
from aegis.agents import monitoring_score  # noqa: E402
from aegis.evaluation import confusion  # noqa: E402

DEV_SEED = 21
WINDOWS_PER_FILE = 50
BUDGET = 0.05


def normal_windows(dataset_id, judged, ablate):
    rng = np.random.default_rng(anomaly.SEED)
    blocked = [(w["row_start"] - anomaly.GUARD_ROWS - 100, w["row_end"] + anomaly.GUARD_ROWS) for w in judged]
    local, _ = anomaly._sample(dataset_id, 100, ablate, rng, anomaly.SAME_NETWORK_SAMPLES, blocked)
    return local


def main() -> None:
    from sklearn.covariance import MinCovDet
    from sklearn.ensemble import IsolationForest
    from sklearn.neighbors import LocalOutlierFactor
    from sklearn.preprocessing import RobustScaler, StandardScaler
    from sklearn.svm import OneClassSVM

    results = {}
    for ablate in (False, True):
        for dataset_id in anomaly.usable_files():
            judged = data.load_windows(dataset_id, WINDOWS_PER_FILE, 100, seed=DEV_SEED, ablate_tcp_window=ablate)
            normal = normal_windows(dataset_id, judged, ablate)
            if len(normal) < 50:
                normal += anomaly._other_days(tuple(anomaly.usable_files(exclude=dataset_id)), 100, ablate)["benign"][:800]
            keys = sorted(k for k in normal[0] if k != "flows")
            x = np.array([[f[k] for k in keys] for f in normal], float)
            t = np.array([[w["features"][k] for k in keys] for w in judged], float)
            truth = [w["truth"]["is_attack"] for w in judged]
            rng = np.random.default_rng(7)
            order = rng.permutation(len(x))
            train, held = x[order[: int(len(x) * 0.8)]], x[order[int(len(x) * 0.8):]]

            def scored(name, fit_score):
                held_scores, test_scores = fit_score(train, held, t)
                limit = np.quantile(held_scores, 1 - BUDGET)
                results.setdefault((name, ablate), {"truth": [], "pred": [], "score": []})
                r = results[(name, ablate)]
                r["truth"] += truth
                r["pred"] += list(test_scores > limit)
                r["score"] += list(test_scores)

            def iforest(tr, ho, te):
                sc = StandardScaler().fit(tr)
                m = IsolationForest(n_estimators=200, random_state=7).fit(sc.transform(tr))
                return -m.score_samples(sc.transform(ho)), -m.score_samples(sc.transform(te))

            def lof(tr, ho, te):
                sc = RobustScaler().fit(tr)
                m = LocalOutlierFactor(n_neighbors=20, novelty=True).fit(sc.transform(tr))
                return -m.score_samples(sc.transform(ho)), -m.score_samples(sc.transform(te))

            def ocsvm(tr, ho, te):
                sc = StandardScaler().fit(tr)
                m = OneClassSVM(nu=0.05, gamma="scale").fit(sc.transform(tr))
                return -m.score_samples(sc.transform(ho)), -m.score_samples(sc.transform(te))

            def mahalanobis(tr, ho, te):
                sc = RobustScaler().fit(tr)
                m = MinCovDet(random_state=7).fit(sc.transform(tr) + rng.normal(0, 1e-6, tr.shape))
                return m.mahalanobis(sc.transform(ho)), m.mahalanobis(sc.transform(te))

            def ensemble(tr, ho, te):
                # Rank-average of the three distance-style detectors.
                parts = [iforest(tr, ho, te), lof(tr, ho, te), mahalanobis(tr, ho, te)]
                out_h, out_t = np.zeros(len(ho)), np.zeros(len(te))
                for h, s in parts:
                    ref = np.sort(h)
                    out_h += np.searchsorted(ref, h) / len(ref)
                    out_t += np.searchsorted(ref, s) / len(ref)
                return out_h / 3, out_t / 3

            for name, fn in (("isolation forest (current)", iforest), ("local outlier factor", lof), ("one-class SVM", ocsvm),
                             ("robust Mahalanobis", mahalanobis), ("ensemble IF+LOF+Mahalanobis", ensemble)):
                scored(name, fn)
            key = ("rules (score >= 0.75)", ablate)
            if True:
                results.setdefault(key, {"truth": [], "pred": [], "score": []})
                r = results[key]
                r["truth"] += truth
                r["pred"] += [monitoring_score(w["features"]) >= 0.75 for w in judged]
                r["score"] += [monitoring_score(w["features"]) for w in judged]

    # Combinations with the rules: both must agree (AND), or either (OR). Same windows, same order.
    for rules_ablate in (False, True):
      rules = results[("rules (score >= 0.75)", rules_ablate)]
      tag = "" if rules_ablate else " [rules use TCP window]"
      for name in ("isolation forest (current)", "one-class SVM"):
        det = results[(name, True)]
        for how, op in (("AND rules", np.logical_and), ("OR rules", np.logical_or)):
            results[(f"{name.split(' (')[0]} {how}{tag}", True)] = {
                "truth": det["truth"], "pred": list(op(det["pred"], rules["pred"])), "score": det["score"]}
        for gate in (0.5, 0.6, 0.65):
            results[(f"{name.split(' (')[0]} AND homogeneity>={gate}{tag}", True)] = {
                "truth": det["truth"], "pred": [p and s >= gate for p, s in zip(det["pred"], rules["score"])], "score": det["score"]}

    print(f"{'detector':<44}{'TCP-window feature':>20}{'MCC':>8}{'recall':>8}{'FPR':>8}{'F1':>8}")
    for (name, ablate), r in sorted(results.items(), key=lambda kv: -(confusion(kv[1]["truth"], kv[1]["pred"])["mcc"] or -1)):
        m = confusion(r["truth"], r["pred"])
        print(f"{name:<44}{'removed' if ablate else 'kept':>20}{m['mcc']:>8}{m['recall']:>8}{m['false_positive_rate']:>8}{m['f1']:>8}")


if __name__ == "__main__":
    main()

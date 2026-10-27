"""Development experiment: which way of naming the attack family works best?

    python scripts/typing_experiment.py

Leave-one-day-out over every usable day-file: classifiers are trained on
labelled attack windows from the other days (sampling seed 11) and tested on
attack windows from the held-out day drawn with a different seed (21). These
development windows are separate from the benchmark windows, so the final
benchmark on fresh seeds stays an honest test.

Scoring: a window whose family never appears in the training days can only be
answered correctly with "Unknown" (open-set accuracy). We also report plain
accuracy, macro-F1, the abstention rate and accuracy on answered windows.
"""

import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aegis import anomaly, data, family  # noqa: E402
from aegis.evaluation import expected_attack_type  # noqa: E402

DEV_TEST_SEED = 21


def old_style(files, window_size, seed):
    """The current method's inputs: anomaly-detector features of labelled windows."""
    out = []
    for dataset_id in files:
        frame = data._frame(dataset_id)
        rng = np.random.default_rng(seed)
        for start in rng.integers(0, len(frame) - window_size, family.SAMPLES_PER_FILE):
            chunk = frame.iloc[int(start) : int(start) + window_size]
            truth = data.ground_truth(chunk)
            if truth["is_attack"]:
                labels = {k: v for k, v in truth["label_counts"].items() if k != "Benign"}
                out.append((data.summarize(chunk), expected_attack_type(max(labels, key=labels.get)), dataset_id))
                if sum(1 for _, _, d in out if d == dataset_id) >= family.MAX_PER_FILE:
                    break
    return out


def matrix(rows, names):
    return np.array([[r[n] for n in names] for r in rows], float)


def main() -> None:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import f1_score
    from sklearn.neighbors import KNeighborsClassifier, NeighborhoodComponentsAnalysis
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import RobustScaler, StandardScaler

    files = anomaly.usable_files()
    size = 100
    print("Building labelled windows…", flush=True)
    new_train = {f: family.labelled_windows(f, size, seed=family.SEED) for f in files}
    new_test = {f: family.labelled_windows(f, size, seed=DEV_TEST_SEED) for f in files}
    old_train = {f: [(x, y) for x, y, _ in old_style([f], size, family.SEED)] for f in files}
    old_test = {f: [(x, y) for x, y, _ in old_style([f], size, DEV_TEST_SEED)] for f in files}

    results = defaultdict(lambda: {"truth": [], "pred": [], "known": []})
    for held in files:
        if not new_test[held]:
            continue
        train_new = [r for f in files if f != held for r in new_train[f]]
        train_old = [r for f in files if f != held for r in old_train[f]]
        known = {y for _, y in train_new}
        x_new, y_new = [x for x, _ in train_new], [y for _, y in train_new]
        names_new = sorted(x_new[0])
        test_x = [x for x, _ in new_test[held]]
        test_y = [y for _, y in new_test[held]]

        def record(method, preds, truths=test_y):
            for t, p in zip(truths, preds):
                results[method]["truth"].append(t)
                results[method]["pred"].append(p)
                results[method]["known"].append(t in known)

        # 1. Current: 5-NN on anomaly features, majority of the top 3.
        if old_test[held]:
            names_old = sorted(train_old[0][0])
            sc = StandardScaler().fit(matrix([x for x, _ in train_old], names_old))
            knn = KNeighborsClassifier(n_neighbors=3).fit(
                sc.transform(matrix([x for x, _ in train_old], names_old)), [y for _, y in train_old]
            )
            record("current kNN (old features)", knn.predict(sc.transform(matrix([x for x, _ in old_test[held]], names_old))),
                   [y for _, y in old_test[held]])

        xm, tm = matrix(x_new, names_new), matrix(test_x, names_new)
        rs = RobustScaler().fit(xm)
        # 2. Distance-weighted kNN, new features.
        record("kNN weighted (new features)",
               KNeighborsClassifier(n_neighbors=7, weights="distance").fit(rs.transform(xm), y_new).predict(rs.transform(tm)))
        # 3. NCA metric + kNN.
        nca = make_pipeline(RobustScaler(), NeighborhoodComponentsAnalysis(random_state=0),
                            KNeighborsClassifier(n_neighbors=7, weights="distance"))
        record("NCA + kNN (new features)", nca.fit(xm, y_new).predict(tm))
        # 4. Random Forest.
        rf = RandomForestClassifier(n_estimators=300, class_weight="balanced", min_samples_leaf=2, random_state=11, n_jobs=-1)
        record("Random Forest (new features)", rf.fit(rs.transform(xm), y_new).predict(rs.transform(tm)))
        # 5/6. The proposed classifier: RF + kNN soft vote, closed and open set.
        clf = family.FamilyClassifier().fit(x_new, y_new)
        out = [clf.predict(x) for x in test_x]
        record("RF + kNN vote (closed set)", [o["candidates"][0]["family"] for o in out])
        record("RF + kNN vote + Unknown (open set)", [o["family"] for o in out])

    print(f"\nHeld-out windows per day: {dict((f.split('_')[0], len(new_test[f])) for f in files)}\n")
    print(f"{'Method':<40}{'n':>5}{'acc':>7}{'open-set acc':>14}{'macro-F1':>10}{'abstain':>9}{'acc answered':>14}")
    for method, r in results.items():
        t, p, known = np.array(r["truth"]), np.array(r["pred"]), np.array(r["known"])
        correct = p == t
        open_correct = np.where(known, correct, p == "Unknown")
        answered = p != "Unknown"
        open_truth = np.where(known, t, "Unknown")
        f1 = f1_score(open_truth, p, average="macro", zero_division=0)
        acc_ans = correct[answered].mean() if answered.any() else float("nan")
        print(f"{method:<40}{len(t):>5}{correct.mean():>7.3f}{open_correct.mean():>14.3f}{f1:>10.3f}"
              f"{1 - answered.mean():>9.3f}{acc_ans:>14.3f}")
    print("\nConfusions of the open-set classifier (truth -> predicted):")
    r = results["RF + kNN vote + Unknown (open set)"]
    print(dict(Counter(f"{t} -> {p}" for t, p in zip(r["truth"], r["pred"]) if t != p).most_common(12)))


if __name__ == "__main__":
    main()

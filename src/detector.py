"""
Milestone 2 - the detection model.

    python -m src.detector                  # train + evaluate RT-IoT2022
    python -m src.detector --dataset NAME

What it does:
 1. Compares Logistic Regression, Random Forest and XGBoost with 5-fold
    stratified cross-validation on the TRAINING part only.
    (Cross-validation = split the training data into 5 parts, train on 4 and
    score on the 5th, five times. Every training row is scored exactly once,
    by a model that did not see it: an "out-of-fold" prediction.)
 2. Leakage check, also inside cross-validation: retrain XGBoost without the
    port column(s) and compare.
 3. Trains the final model on all training rows and scores the test set ONCE.
 4. Saves the model and every table/figure under models/<dataset>/ and
    eval/results/<dataset>/.

Everything else in the project uses the model only through detect(sample).
"""

import argparse
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

import joblib
import matplotlib
matplotlib.use("Agg")   # draw figures to files, no window
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import sklearn
import xgboost as xgb
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, f1_score, precision_recall_fscore_support
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import LabelEncoder, OneHotEncoder, StandardScaler
from sklearn.utils.class_weight import compute_sample_weight

from src.config import DEFAULT_DATASET, dataset_paths, get_dataset_config

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("detector")

SEED = 42
N_FOLDS = 5
LOW_CONFIDENCE = 0.60   # below this, detect() raises the low-confidence flag
RF_CLEARLY_BETTER = 0.01  # RF replaces XGBoost only if its CV macro-F1 is >1 point higher


# ---------------------------------------------------------------------------
# Preprocessing
# ---------------------------------------------------------------------------
def make_preprocessor(categorical: List[str], numeric: List[str], scale: bool) -> ColumnTransformer:
    """One-hot encode the text columns. Scale numbers only when asked
    (Logistic Regression needs it; tree models do not)."""
    return ColumnTransformer(
        [("cat", OneHotEncoder(handle_unknown="ignore", sparse_output=False), categorical),
         ("num", StandardScaler() if scale else "passthrough", numeric)],
        verbose_feature_names_out=False,   # keep readable names such as "service_http"
    )


def make_model(name: str):
    """The three models, with sensible defaults (no big hyper-parameter search)."""
    if name == "Logistic Regression":
        return LogisticRegression(class_weight="balanced", max_iter=3000, random_state=SEED)
    if name == "Random Forest":
        return RandomForestClassifier(n_estimators=200, class_weight="balanced",
                                      random_state=SEED, n_jobs=-1)
    if name == "XGBoost":
        return xgb.XGBClassifier(n_estimators=200, max_depth=6, learning_rate=0.1,
                                 tree_method="hist", random_state=SEED, n_jobs=-1)
    raise ValueError(name)


def fit_model(name, X_df, y, categorical, numeric):
    """Fit preprocessor + model. XGBoost has no class_weight option, so it gets
    'balanced' sample weights instead (rare classes count more)."""
    prep = make_preprocessor(categorical, numeric, scale=(name == "Logistic Regression"))
    X = prep.fit_transform(X_df)
    model = make_model(name)
    if name == "XGBoost":
        model.fit(X, y, sample_weight=compute_sample_weight("balanced", y))
    else:
        model.fit(X, y)
    return prep, model


def out_of_fold_predictions(name, X_df, y, categorical, numeric):
    """5-fold stratified CV. Returns (out-of-fold predictions, per-fold macro-F1, mean fit seconds)."""
    skf = StratifiedKFold(n_splits=N_FOLDS, shuffle=True, random_state=SEED)
    oof = np.empty_like(y)
    fold_f1, times = [], []
    all_classes = np.arange(int(y.max()) + 1)
    for tr, va in skf.split(X_df, y):
        t0 = time.time()
        prep, model = fit_model(name, X_df.iloc[tr], y[tr], categorical, numeric)
        times.append(time.time() - t0)
        oof[va] = model.predict(prep.transform(X_df.iloc[va]))
        # labels=all classes, so a fold that happens to hold no row of a rare
        # class still averages over all 12 classes (that class scores 0 there).
        fold_f1.append(f1_score(y[va], oof[va], labels=all_classes, average="macro", zero_division=0))
    return oof, fold_f1, float(np.mean(times))


def per_class_table(y_true, y_pred, class_names) -> pd.DataFrame:
    p, r, f, n = precision_recall_fscore_support(
        y_true, y_pred, labels=np.arange(len(class_names)), zero_division=0)
    return pd.DataFrame({"precision": p, "recall": r, "f1": f, "rows": n}, index=class_names).round(4)


def false_alarm_rate(y_true_lbl, y_pred_lbl, family: Dict[str, str]) -> Dict[str, Any]:
    """Share of truly normal flows that the model calls an attack."""
    is_normal = np.array([family.get(l) == "Normal" for l in y_true_lbl])
    pred_attack = np.array([family.get(l) != "Normal" for l in y_pred_lbl])
    n_normal = int(is_normal.sum())
    n_false = int((is_normal & pred_attack).sum())
    return {"false_alarms": n_false, "normal_flows": n_normal,
            "false_alarm_rate": n_false / n_normal if n_normal else 0.0}


# ---------------------------------------------------------------------------
# Training workflow
# ---------------------------------------------------------------------------
def train_and_evaluate(dataset: str = DEFAULT_DATASET) -> Dict[str, Any]:
    cfg = get_dataset_config(dataset)
    paths = dataset_paths(dataset)
    for k in ("models_dir", "results_dir", "plots_dir"):
        paths[k].mkdir(parents=True, exist_ok=True)

    label = cfg["label_column"]
    family = cfg["label_to_family"]
    train_df = pd.read_parquet(paths["train"])
    test_df = pd.read_parquet(paths["test"])

    X_train = train_df.drop(columns=[label])
    X_test = test_df.drop(columns=[label, "sample_id"])
    categorical = [c for c in cfg.get("categorical_columns", []) if c in X_train.columns]
    numeric = [c for c in X_train.columns if c not in categorical]

    encoder = LabelEncoder().fit(train_df[label])
    class_names = encoder.classes_.tolist()
    y_train = encoder.transform(train_df[label])
    y_test = encoder.transform(test_df[label])

    # ---- Step 1: compare three models with cross-validation -------------------
    print("\n" + "=" * 78 + "\nSTEP 1  5-fold cross-validation on the training part only\n" + "=" * 78)
    comparison, cv_per_class, oof_by_model = [], {}, {}
    for name in ["Logistic Regression", "Random Forest", "XGBoost"]:
        logger.info("Cross-validating %s ...", name)
        oof, fold_f1, fit_s = out_of_fold_predictions(name, X_train, y_train, categorical, numeric)
        oof_by_model[name] = oof
        pooled = f1_score(y_train, oof, average="macro")
        comparison.append({"model": name,
                           "macro_f1_pooled": round(pooled, 4),
                           "macro_f1_fold_mean": round(float(np.mean(fold_f1)), 4),
                           "macro_f1_fold_std": round(float(np.std(fold_f1)), 4),
                           "accuracy": round(float((oof == y_train).mean()), 4),
                           "fit_seconds_per_fold": round(fit_s, 2)})
        cv_per_class[name] = per_class_table(y_train, oof, class_names)
    comp_df = pd.DataFrame(comparison)
    print(comp_df.to_string(index=False))

    xgb_f1 = comp_df.set_index("model").loc["XGBoost", "macro_f1_pooled"]
    rf_f1 = comp_df.set_index("model").loc["Random Forest", "macro_f1_pooled"]
    chosen = "Random Forest" if rf_f1 - xgb_f1 > RF_CLEARLY_BETTER else "XGBoost"
    print(f"\nChosen for the app: {chosen} "
          f"(Random Forest replaces XGBoost only if >{RF_CLEARLY_BETTER:.0%} better; "
          f"RF {rf_f1:.4f} vs XGB {xgb_f1:.4f})")
    if chosen != "XGBoost":
        logger.warning("Random Forest won. detect() is written for XGBoost (pred_contribs); "
                       "switching would need the shap package - see PLAN.md.")

    print("\nPer-class scores of XGBoost from POOLED out-of-fold predictions "
          "(the reliable numbers for the rare classes):")
    print(cv_per_class["XGBoost"].to_string())

    # ---- Step 2: leakage check (inside CV, so the test set stays untouched) ----
    print("\n" + "=" * 78 + "\nSTEP 2  Leakage check: XGBoost without the port column(s)\n" + "=" * 78)
    ports = [c for c in cfg.get("port_columns", []) if c in X_train.columns]
    oof_np, _, _ = out_of_fold_predictions("XGBoost", X_train.drop(columns=ports), y_train,
                                          categorical, [c for c in numeric if c not in ports])
    f1_no_port = f1_score(y_train, oof_np, average="macro")
    # (the source port was already removed for every model by the data loader)
    leakage = {"ports_removed_here": ports,
               "cv_macro_f1_with_ports": round(float(xgb_f1), 4),
               "cv_macro_f1_without_ports": round(float(f1_no_port), 4),
               "difference": round(float(xgb_f1 - f1_no_port), 4),
               "per_class_without_ports": per_class_table(y_train, oof_np, class_names)["f1"].to_dict()}
    print(f"CV macro-F1 with destination port:    {xgb_f1:.4f}")
    print(f"CV macro-F1 without any port column:  {f1_no_port:.4f}")
    print(f"Difference:                           {xgb_f1 - f1_no_port:+.4f}")

    # ---- Step 3: final model, test set scored once ------------------------------
    print("\n" + "=" * 78 + "\nSTEP 3  Final XGBoost on all training rows; test set scored ONCE\n" + "=" * 78)
    prep, model = fit_model("XGBoost", X_train, y_train, categorical, numeric)
    model.save_model(str(paths["model"]))
    joblib.dump({"preprocessor": prep, "label_encoder": encoder,
                 "feature_names": prep.get_feature_names_out().tolist(),
                 "input_columns": X_train.columns.tolist()}, paths["preprocessor"])

    pred = model.predict(prep.transform(X_test))
    pred_lbl = encoder.inverse_transform(pred)
    test_macro = f1_score(y_test, pred, average="macro")
    test_table = per_class_table(y_test, pred, class_names)
    test_table["cv_f1"] = cv_per_class["XGBoost"]["f1"]
    test_table["cv_rows"] = cv_per_class["XGBoost"]["rows"]
    far = false_alarm_rate(test_df[label].values, pred_lbl, family)
    cm = pd.DataFrame(confusion_matrix(y_test, pred, labels=np.arange(len(class_names))),
                      index=class_names, columns=class_names)

    print(f"HEADLINE  test macro-F1 = {test_macro:.4f}   accuracy = {(pred == y_test).mean():.4f}")
    print(f"False alarm rate = {far['false_alarm_rate']:.2%} "
          f"({far['false_alarms']} of {far['normal_flows']} normal flows flagged as an attack)\n")
    print(test_table.to_string())
    noisy = test_table[test_table["rows"] < 20].index.tolist()
    if noisy:
        print(f"\nNOTE: {noisy} have fewer than 20 test rows, so their test scores are very noisy "
              "(one row can move F1 by a lot). Quote their cross-validation scores (cv_f1) instead.")

    # ---- Save everything ---------------------------------------------------------
    rd = paths["results_dir"]
    comp_df.to_csv(rd / "model_comparison.csv", index=False)
    pd.concat({m: t for m, t in cv_per_class.items()}, axis=1).to_csv(rd / "cv_per_class.csv")
    test_table.to_csv(rd / "test_per_class.csv", index_label="label")
    cm.to_csv(rd / "confusion_matrix.csv")
    plot_confusion_matrix(cm, test_macro, paths["plots_dir"] / "confusion_matrix.png")
    metrics = {
        "dataset": cfg["dataset_name"],
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "versions": {"xgboost": xgb.__version__, "scikit-learn": sklearn.__version__},
        "train_rows": int(len(train_df)), "test_rows": int(len(test_df)),
        "chosen_model": chosen,
        "cv_comparison": comparison,
        "test": {"macro_f1": round(float(test_macro), 4),
                 "accuracy": round(float((pred == y_test).mean()), 4),
                 **far},
        "leakage_check": leakage,
    }
    with open(rd / "detector_metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)
    logger.info("Saved model to %s and results to %s", paths["model"], rd)
    return metrics


def plot_confusion_matrix(cm: pd.DataFrame, macro_f1: float, path) -> None:
    fig, ax = plt.subplots(figsize=(11, 9))
    # log colour scale so that small counts are still visible next to big ones
    im = ax.imshow(np.log1p(cm.values), cmap="Blues")
    ax.set_xticks(range(len(cm)), cm.columns, rotation=45, ha="right")
    ax.set_yticks(range(len(cm)), cm.index)
    for i in range(len(cm)):
        for j in range(len(cm)):
            v = cm.values[i, j]
            if v:
                ax.text(j, i, str(v), ha="center", va="center", fontsize=8,
                        color="white" if np.log1p(v) > np.log1p(cm.values.max()) / 2 else "black")
    ax.set_xlabel("Predicted label")
    ax.set_ylabel("True label")
    ax.set_title(f"XGBoost confusion matrix, test set (macro-F1 {macro_f1:.3f})")
    fig.colorbar(im, ax=ax, label="log(1 + count)")
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


# ---------------------------------------------------------------------------
# detect(): the ONLY way the rest of the project uses the model
# ---------------------------------------------------------------------------
_LOADED: Dict[str, Dict[str, Any]] = {}
_CUSTOM_SAMPLES: Dict[str, pd.Series] = {}


def store_custom_sample(sample_id: str, row: Union[pd.Series, Dict[str, Any]]) -> None:
    """Store an uploaded or simulated sample so load_test_sample can retrieve it."""
    if not isinstance(row, pd.Series):
        row = pd.Series(row)
    _CUSTOM_SAMPLES[sample_id] = row


def _load(dataset: str) -> Dict[str, Any]:
    """Load model + preprocessor once per dataset and keep them in memory."""
    if dataset not in _LOADED:
        paths = dataset_paths(dataset)
        if not paths["model"].exists():
            raise FileNotFoundError(f"No trained detector for '{dataset}'. "
                                    f"Run: python -m src.detector --dataset {dataset}")
        model = xgb.XGBClassifier()
        model.load_model(str(paths["model"]))
        bundle = joblib.load(paths["preprocessor"])
        bundle["model"] = model
        bundle["config"] = get_dataset_config(dataset)
        _LOADED[dataset] = bundle
    return _LOADED[dataset]


def detect(sample: Union[Dict[str, Any], pd.Series, pd.DataFrame],
           dataset: str = DEFAULT_DATASET) -> Dict[str, Any]:
    """Classify ONE traffic flow.

    `sample` holds the flow's feature values (a dict, a pandas row, or a
    one-row DataFrame). Extra keys such as sample_id or the true label are ignored.

    Returns a dict with:
      sample_id, predicted_label, is_attack, attack_family, confidence,
      top_3 [(label, probability)], low_confidence (bool),
      top_features [{feature, value, contribution}] (the 5 that pushed hardest
      towards the predicted label, from XGBoost's pred_contribs).
    """
    b = _load(dataset)
    cfg = b["config"]
    if isinstance(sample, pd.DataFrame):
        sample = sample.iloc[0]
    row = dict(sample)
    sample_id = row.get("sample_id")

    def _default_col_val(col: str):
        if col == "proto":
            return "tcp"
        if col == "service":
            return "-"
        return 0.0

    row_data = {}
    for c in b["input_columns"]:
        if c in row and row[c] is not None and not (isinstance(row[c], float) and np.isnan(row[c])):
            row_data[c] = row[c]
        else:
            row_data[c] = _default_col_val(c)
    X_df = pd.DataFrame([row_data])

    X = b["preprocessor"].transform(X_df)
    probs = b["model"].predict_proba(X)[0]
    classes = b["label_encoder"].classes_.tolist()
    order = np.argsort(probs)[::-1]
    best = int(order[0])
    label = classes[best]
    fam = cfg["label_to_family"].get(label, "Other")

    # pred_contribs gives, for every class, each feature's push on that class's
    # score (SHAP values computed exactly for trees). Shape: (1, classes, features + bias).
    contribs = b["model"].get_booster().predict(xgb.DMatrix(X), pred_contribs=True)[0, best, :-1]
    top = np.argsort(-contribs)[:5]   # strongest push TOWARDS the predicted label
    names = b["feature_names"]
    top_features = []
    for i in top:
        name = names[i]
        value = row[name] if name in row else float(X[0, i])   # one-hot columns: 1.0 or 0.0
        if isinstance(value, (np.integer, np.floating)):
            value = value.item()
        top_features.append({"feature": name, "value": value, "contribution": round(float(contribs[i]), 4)})

    confidence = float(probs[best])
    return {
        "dataset": dataset,
        "sample_id": sample_id,
        "predicted_label": label,
        "is_attack": fam != "Normal",
        "attack_family": fam,
        "confidence": round(confidence, 4),
        "top_3": [(classes[i], round(float(probs[i]), 4)) for i in order[:3]],
        "probabilities": {c: round(float(p), 4) for c, p in zip(classes, probs)},   # all labels (the app animates these)
        "low_confidence": confidence < LOW_CONFIDENCE,
        "top_features": top_features,
    }


def load_test_sample(sample_id: str, dataset: str = DEFAULT_DATASET) -> Optional[pd.Series]:
    """Fetch one row of the test pool by its sample ID (None if it does not exist)."""
    if sample_id in _CUSTOM_SAMPLES:
        return _CUSTOM_SAMPLES[sample_id]
    b = _load(dataset)
    if "test_df" not in b:
        b["test_df"] = pd.read_parquet(dataset_paths(dataset)["test"]).set_index("sample_id", drop=False)
    df = b["test_df"]
    return df.loc[sample_id] if sample_id in df.index else None


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset", default=DEFAULT_DATASET)
    train_and_evaluate(ap.parse_args().dataset)

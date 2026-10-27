"""
Compare ML algorithms for PhishShield URL Threat Analysis using domain-grouped CV.
Compares: Logistic Regression, Random Forest, HistGradientBoosting.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.model_selection import GroupKFold
from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score, average_precision_score

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

project_root = Path(__file__).resolve().parent.parent
PROCESSED_DIR = project_root / "data" / "processed"
REPORTS_DIR = project_root / "reports"


def run_comparison():
    train_meta = pd.read_csv(PROCESSED_DIR / "train_meta.csv")
    train_feat = pd.read_csv(PROCESSED_DIR / "train_features.csv")

    X = train_feat.values
    y = train_meta["label"].values
    groups = train_meta["registrable_domain"].values

    models = {
        "LogisticRegression": LogisticRegression(max_iter=1000, class_weight="balanced", random_state=42),
        "RandomForest": RandomForestClassifier(n_estimators=100, max_depth=12, class_weight="balanced", random_state=42),
        "HistGradientBoosting": HistGradientBoostingClassifier(max_iter=150, max_depth=8, class_weight="balanced", random_state=42),
    }

    gkf = GroupKFold(n_splits=4)
    results = {}

    for name, clf in models.items():
        logger.info(f"Evaluating {name} with 4-fold domain-grouped CV...")
        precisions = []
        recalls = []
        f1s = []
        aucs = []
        pr_aucs = []

        for fold, (t_idx, v_idx) in enumerate(gkf.split(X, y, groups)):
            X_t, y_t = X[t_idx], y[t_idx]
            X_v, y_v = X[v_idx], y[v_idx]

            clf.fit(X_t, y_t)
            probs = clf.predict_proba(X_v)[:, 1]
            preds = (probs >= 0.5).astype(int)

            precisions.append(precision_score(y_v, preds, zero_division=0))
            recalls.append(recall_score(y_v, preds, zero_division=0))
            f1s.append(f1_score(y_v, preds, zero_division=0))
            aucs.append(roc_auc_score(y_v, probs))
            pr_aucs.append(average_precision_score(y_v, probs))

        results[name] = {
            "mean_precision": float(np.mean(precisions)),
            "std_precision": float(np.std(precisions)),
            "mean_recall": float(np.mean(recalls)),
            "std_recall": float(np.std(recalls)),
            "mean_f1": float(np.mean(f1s)),
            "std_f1": float(np.std(f1s)),
            "mean_roc_auc": float(np.mean(aucs)),
            "std_roc_auc": float(np.std(aucs)),
            "mean_pr_auc": float(np.mean(pr_aucs)),
            "std_pr_auc": float(np.std(pr_aucs)),
        }
        logger.info(f"Result for {name}: F1={results[name]['mean_f1']:.4f}, AUC={results[name]['mean_roc_auc']:.4f}, PR-AUC={results[name]['mean_pr_auc']:.4f}")

    out_file = REPORTS_DIR / "model_comparison.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    logger.info(f"Saved model comparison to {out_file}")


if __name__ == "__main__":
    run_comparison()

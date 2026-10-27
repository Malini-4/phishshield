"""
Train the production PhishShield URL Threat Analysis model with probability calibration
and threshold optimization on validation data.
"""
from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV, calibration_curve
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import (
    brier_score_loss,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    average_precision_score,
)

project_root = Path(__file__).resolve().parent.parent
backend_dir = project_root / "backend"
sys.path.insert(0, str(backend_dir))

from app.security.url_features import FEATURE_NAMES

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

PROCESSED_DIR = project_root / "data" / "processed"
MODELS_DIR = project_root / "models"
REPORTS_DIR = project_root / "reports"

MODELS_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def train():
    logger.info("=== Phase 2: Training URL Threat Model ===")

    train_meta = pd.read_csv(PROCESSED_DIR / "train_meta.csv")
    train_feat = pd.read_csv(PROCESSED_DIR / "train_features.csv")[FEATURE_NAMES]

    val_meta = pd.read_csv(PROCESSED_DIR / "val_meta.csv")
    val_feat = pd.read_csv(PROCESSED_DIR / "val_features.csv")[FEATURE_NAMES]

    # Verify feature names contract
    assert list(train_feat.columns) == FEATURE_NAMES
    assert list(val_feat.columns) == FEATURE_NAMES

    X_train = train_feat.values
    y_train = train_meta["label"].values

    X_val = val_feat.values
    y_val = val_meta["label"].values

    logger.info(f"Training set: {X_train.shape[0]} samples, {X_train.shape[1]} features")
    logger.info(f"Validation set: {X_val.shape[0]} samples")

    # Base estimator: HistGradientBoosting
    base_clf = HistGradientBoostingClassifier(
        max_iter=150,
        max_depth=8,
        min_samples_leaf=15,
        class_weight="balanced",
        random_state=42,
    )

    # Probability calibration using 5-fold cross-validation on training data
    calibrator = CalibratedClassifierCV(estimator=base_clf, method="sigmoid", cv=5)
    calibrator.fit(X_train, y_train)

    # Evaluate calibration & probability distribution on validation
    val_probs = calibrator.predict_proba(X_val)[:, 1]
    brier = brier_score_loss(y_val, val_probs)
    val_auc = roc_auc_score(y_val, val_probs)
    val_pr_auc = average_precision_score(y_val, val_probs)
    logger.info(f"Validation Brier score: {brier:.4f}, ROC-AUC: {val_auc:.4f}, PR-AUC: {val_pr_auc:.4f}")

    # Threshold selection on validation data:
    # suspicious_threshold: high recall operating point (~0.35)
    # malicious_threshold: high precision operating point (>= 0.75)
    best_sus_thresh = 0.35
    best_mal_thresh = 0.80

    for t in np.linspace(0.2, 0.5, 31):
        preds = (val_probs >= t).astype(int)
        r = recall_score(y_val, preds, zero_division=0)
        if r >= 0.95:
            best_sus_thresh = float(t)
            break

    for t in np.linspace(0.70, 0.95, 26):
        preds = (val_probs >= t).astype(int)
        p = precision_score(y_val, preds, zero_division=0)
        if p >= 0.98:
            best_mal_thresh = float(t)
            break

    logger.info(f"Selected operating thresholds on validation data: suspicious={best_sus_thresh:.3f}, malicious={best_mal_thresh:.3f}")

    # Compute calibration reliability table
    prob_true, prob_pred = calibration_curve(y_val, val_probs, n_bins=10)
    reliability_table = [
        {"bin": i + 1, "mean_predicted_prob": float(prob_pred[i]), "fraction_positives": float(prob_true[i])}
        for i in range(len(prob_pred))
    ]

    # Save model artifact
    model_path = MODELS_DIR / "url_model.joblib"
    joblib.dump(calibrator, model_path)
    logger.info(f"Saved calibrated model pipeline to {model_path}")

    # Save model metadata
    model_version = f"v1.0.0-{datetime.now(timezone.utc).strftime('%Y%m%d')}-hgb"
    meta = {
        "model_version": model_version,
        "algorithm": "HistGradientBoostingClassifier + CalibratedClassifierCV(sigmoid)",
        "feature_names": FEATURE_NAMES,
        "num_features": len(FEATURE_NAMES),
        "suspicious_threshold": best_sus_thresh,
        "malicious_threshold": best_mal_thresh,
        "validation_metrics": {
            "brier_score": float(brier),
            "roc_auc": float(val_auc),
            "pr_auc": float(val_pr_auc),
        },
        "calibration_reliability_curve": reliability_table,
        "dataset_counts": {
            "train_samples": len(train_meta),
            "val_samples": len(val_meta),
            "train_domains": int(train_meta["registrable_domain"].nunique()),
            "val_domains": int(val_meta["registrable_domain"].nunique()),
        },
        "training_date": datetime.now(timezone.utc).isoformat(),
        "library_versions": {
            "scikit_learn": pd.__version__,
            "joblib": joblib.__version__,
        },
    }

    meta_path = MODELS_DIR / "url_model_meta.json"
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
    logger.info(f"Saved model metadata to {meta_path}")

    logger.info("=== Model Training Completed Successfully ===")


if __name__ == "__main__":
    train()

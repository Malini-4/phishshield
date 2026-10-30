"""Train SMS scam language classification model and report comprehensive evaluation."""
from __future__ import annotations

import os
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    brier_score_loss,
    classification_report,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupKFold, GroupShuffleSplit

from app.services.sms_ml import MODEL_PATH, MODEL_VERSION, build_pipeline
from app.services.sms_text import normalise_for_model

BASE_DIR = Path(__file__).parent.parent
DATASET_PATH = BASE_DIR / "data" / "sms_training" / "sms_dataset.csv"
STRESS_PATH = BASE_DIR / "data" / "sms_training" / "stress_set.csv"
REAL_PATH = BASE_DIR / "data" / "sms_training" / "real_messages.csv"
DOCS_PATH = BASE_DIR / "docs" / "SMS_MODEL_EVALUATION.md"


def evaluate_predictions(y_true, y_pred, y_prob):
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "auc": float(roc_auc_score(y_true, y_prob)) if len(set(y_true)) > 1 else 0.0,
        "brier": float(brier_score_loss(y_true, y_prob)),
    }


def main():
    print(f"Loading SMS training dataset from {DATASET_PATH}...")
    df = pd.read_csv(DATASET_PATH)
    print(f"Dataset shape: {df.shape}")

    X_raw = df["text"].tolist()
    X_norm = [normalise_for_model(str(t)) for t in X_raw]
    y = df["label"].astype(int).to_numpy()
    groups = df["template_id"].to_numpy()

    # ──────────────────────────────────────────────────────────────────────────
    # (A) Train/Test split by template_id (Unseen template wordings)
    # ──────────────────────────────────────────────────────────────────────────
    print("\n--- (A) Holdout Split by template_id (Unseen Templates) ---")
    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
    train_idx, test_idx = next(gss.split(X_norm, y, groups=groups))

    X_train = [X_norm[i] for i in train_idx]
    y_train = y[train_idx]
    X_test = [X_norm[i] for i in test_idx]
    y_test = y[test_idx]
    test_texts = [X_raw[i] for i in test_idx]

    pipe_holdout = build_pipeline()
    pipe_holdout.fit(X_train, y_train)

    y_test_pred = pipe_holdout.predict(X_test)
    y_test_prob = pipe_holdout.predict_proba(X_test)[:, 1]
    res_holdout = evaluate_predictions(y_test, y_test_pred, y_test_prob)

    print(f"Precision: {res_holdout['precision']:.4f}")
    print(f"Recall:    {res_holdout['recall']:.4f}")
    print(f"F1:        {res_holdout['f1']:.4f}")
    print(f"ROC-AUC:   {res_holdout['auc']:.4f}")
    print(f"Brier:     {res_holdout['brier']:.4f}")

    # List holdout mistakes
    holdout_mistakes = []
    for i in range(len(y_test)):
        if y_test[i] != y_test_pred[i]:
            holdout_mistakes.append({
                "text": test_texts[i],
                "true_label": int(y_test[i]),
                "pred_label": int(y_test_pred[i]),
                "prob": float(y_test_prob[i]),
            })
    print(f"Holdout mistakes count: {len(holdout_mistakes)}")

    # ──────────────────────────────────────────────────────────────────────────
    # (B) GroupKFold(5) by template_id
    # ──────────────────────────────────────────────────────────────────────────
    print("\n--- (B) GroupKFold (5 Folds) by template_id ---")
    gkf = GroupKFold(n_splits=5)
    cv_metrics = {"precision": [], "recall": [], "f1": [], "auc": [], "brier": []}

    for fold, (tr_idx, val_idx) in enumerate(gkf.split(X_norm, y, groups=groups), 1):
        p = build_pipeline()
        p.fit([X_norm[i] for i in tr_idx], y[tr_idx])
        val_probs = p.predict_proba([X_norm[i] for i in val_idx])[:, 1]
        val_preds = (val_probs >= 0.5).astype(int)
        m = evaluate_predictions(y[val_idx], val_preds, val_probs)
        for k in cv_metrics:
            cv_metrics[k].append(m[k])
        print(f"  Fold {fold}: F1={m['f1']:.4f}, Precision={m['precision']:.4f}, Recall={m['recall']:.4f}, AUC={m['auc']:.4f}, Brier={m['brier']:.4f}")

    cv_summary = {k: (float(np.mean(v)), float(np.std(v))) for k, v in cv_metrics.items()}
    print(f"5-Fold CV Mean F1: {cv_summary['f1'][0]:.4f} +/- {cv_summary['f1'][1]:.4f}")

    # ──────────────────────────────────────────────────────────────────────────
    # (C) Stress Set Evaluation (~50 messages NOT from templates)
    # ──────────────────────────────────────────────────────────────────────────
    print("\n--- (C) Stress Set Evaluation ---")
    stress_df = pd.read_csv(STRESS_PATH)
    X_stress_raw = stress_df["text"].tolist()
    X_stress_norm = [normalise_for_model(str(t)) for t in X_stress_raw]
    y_stress = stress_df["label"].astype(int).to_numpy()

    # Train production model on full training set
    full_pipe = build_pipeline()
    full_pipe.fit(X_norm, y)

    # Save to models/
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({
        "pipeline": full_pipe,
        "version": MODEL_VERSION,
        "sklearn_version": joblib.__version__,
    }, MODEL_PATH)
    print(f"Saved full model to {MODEL_PATH}")

    stress_probs = full_pipe.predict_proba(X_stress_norm)[:, 1]
    stress_preds = (stress_probs >= 0.5).astype(int)
    res_stress = evaluate_predictions(y_stress, stress_preds, stress_probs)

    print(f"Stress Set ({len(y_stress)} samples):")
    print(f"Precision: {res_stress['precision']:.4f}")
    print(f"Recall:    {res_stress['recall']:.4f}")
    print(f"F1:        {res_stress['f1']:.4f}")
    print(f"ROC-AUC:   {res_stress['auc']:.4f}")
    print(f"Brier:     {res_stress['brier']:.4f}")

    stress_mistakes = []
    for i in range(len(y_stress)):
        if y_stress[i] != stress_preds[i]:
            stress_mistakes.append({
                "text": X_stress_raw[i],
                "true_label": int(y_stress[i]),
                "pred_label": int(stress_preds[i]),
                "prob": float(stress_probs[i]),
                "category": stress_df.iloc[i].get("category", ""),
            })

    print(f"Stress set mistakes count: {len(stress_mistakes)}")
    for sm in stress_mistakes:
        print(f"  [Mistake] True={sm['true_label']}, Pred={sm['pred_label']}, Prob={sm['prob']:.3f} | {sm['text']}")

    # ──────────────────────────────────────────────────────────────────────────
    # (D) Optional Real Messages
    # ──────────────────────────────────────────────────────────────────────────
    has_real = REAL_PATH.exists()
    real_summary = None
    if has_real:
        try:
            real_df = pd.read_csv(REAL_PATH)
            X_real_norm = [normalise_for_model(str(t)) for t in real_df["text"]]
            y_real = real_df["label"].astype(int).to_numpy()
            real_probs = full_pipe.predict_proba(X_real_norm)[:, 1]
            real_preds = (real_probs >= 0.5).astype(int)
            real_summary = evaluate_predictions(y_real, real_preds, real_probs)
        except Exception as e:
            print(f"Real messages evaluation skipped: {e}")

    # ──────────────────────────────────────────────────────────────────────────
    # Write docs/SMS_MODEL_EVALUATION.md
    # ──────────────────────────────────────────────────────────────────────────
    DOCS_PATH.parent.mkdir(parents=True, exist_ok=True)
    report_content = f"""# SMS Scam Language Model Evaluation Report

**Model Version:** `{MODEL_VERSION}`  
**Architecture:** TF-IDF (char_wb n-grams 2-5 + word n-grams 1-2) with balanced Logistic Regression  
**Feature Normalization:** Shorthand expansion, URL tokenization (`urltoken`), number tokenization (`numtoken`)

> [!WARNING]
> **Synthetic Data Over-statement Warning**:
> High evaluation scores on synthetic and templated datasets typically over-state real-world accuracy due to repeating sentence structures and constrained slot vocabulary. The independent hand-written Stress Set (Section C) provides the true indicator of how the model generalizes to unseen scam formulations and everyday human messaging.

---

## 1. Unseen Template Split (Holdout by `template_id`)
Evaluates model performance when trained on one subset of message templates and tested on completely distinct message templates.

| Metric | Score |
|---|---|
| **Precision** | {res_holdout['precision']:.4f} |
| **Recall** | {res_holdout['recall']:.4f} |
| **F1 Score** | {res_holdout['f1']:.4f} |
| **ROC-AUC** | {res_holdout['auc']:.4f} |
| **Brier Score** | {res_holdout['brier']:.4f} |

### Holdout Mistakes ({len(holdout_mistakes)})
"""
    if holdout_mistakes:
        report_content += "| Text | True Label | Predicted | Prob |\n|---|---|---|---|\n"
        for m in holdout_mistakes[:10]:
            report_content += f"| `{m['text'][:80]}` | {m['true_label']} | {m['pred_label']} | {m['prob']:.4f} |\n"
    else:
        report_content += "No mistakes observed on the holdout template split.\n"

    report_content += f"""
---

## 2. 5-Fold GroupKFold Cross-Validation (by `template_id`)
Cross-validation ensuring that every template group is isolated in the validation fold.

| Metric | Mean | Std Dev |
|---|---|---|
| **Precision** | {cv_summary['precision'][0]:.4f} | ± {cv_summary['precision'][1]:.4f} |
| **Recall** | {cv_summary['recall'][0]:.4f} | ± {cv_summary['recall'][1]:.4f} |
| **F1 Score** | {cv_summary['f1'][0]:.4f} | ± {cv_summary['f1'][1]:.4f} |
| **ROC-AUC** | {cv_summary['auc'][0]:.4f} | ± {cv_summary['auc'][1]:.4f} |
| **Brier Score** | {cv_summary['brier'][0]:.4f} | ± {cv_summary['brier'][1]:.4f} |

---

## 3. Independent Hand-Written Stress Set ({len(y_stress)} Samples)
Evaluation on 50 curated real-world and challenging edge-case messages authored outside the template generator.

| Metric | Score |
|---|---|
| **Precision** | {res_stress['precision']:.4f} |
| **Recall** | {res_stress['recall']:.4f} |
| **F1 Score** | {res_stress['f1']:.4f} |
| **ROC-AUC** | {res_stress['auc']:.4f} |
| **Brier Score** | {res_stress['brier']:.4f} |

### Stress Set Mistakes ({len(stress_mistakes)})
"""
    if stress_mistakes:
        report_content += "| Text | Category | True | Pred | Prob |\n|---|---|---|---|---|\n"
        for sm in stress_mistakes:
            report_content += f"| `{sm['text']}` | {sm['category']} | {sm['true_label']} | {sm['pred_label']} | {sm['prob']:.4f} |\n"
    else:
        report_content += "All 50 stress set test cases correctly classified.\n"

    report_content += f"""
---

## 4. Optional Real Messages
{"Evaluated on real_messages.csv: F1=" + str(real_summary['f1']) if real_summary else "Dataset `real_messages.csv` not provided; evaluation omitted."}

---

## 5. Architectural Guardrails
1. **Never High Severity Solo**: The ML prediction produces at most a `medium` severity evidence item (when probability >= 0.85). It can never trigger a "Likely scam" (`malicious`) verdict on its own.
2. **Resilience**: Shorthand terms (`ur`, `u`, `a/c`, `pls`, `blkd`, `updt`) are normalized before vectorization.
3. **Graceful Degradation**: If `models/sms_model.joblib` cannot be loaded, the rule-based SMS service continues operating without interruption.
"""

    with open(DOCS_PATH, "w", encoding="utf-8") as f:
        f.write(report_content)
    print(f"\nWritten evaluation report to {DOCS_PATH}")


if __name__ == "__main__":
    main()

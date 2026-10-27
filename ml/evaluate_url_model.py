"""
Evaluation script for PhishShield URL Threat Model.
Evaluates once on held-out test set and sanity set; writes real metrics to reports/url_model_metrics.json
and generates docs/MODEL_EVALUATION.md.
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
from sklearn.metrics import (
    confusion_matrix,
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
DOCS_DIR = project_root / "docs"

DOCS_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def evaluate():
    logger.info("=== Phase 2: Evaluating URL Threat Model ===")

    model_path = MODELS_DIR / "url_model.joblib"
    meta_path = MODELS_DIR / "url_model_meta.json"

    if not model_path.exists() or not meta_path.exists():
        raise FileNotFoundError("Model files not found. Run train_url_model.py first.")

    model = joblib.load(model_path)
    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)

    sus_thresh = meta["suspicious_threshold"]
    mal_thresh = meta["malicious_threshold"]

    # 1. Held-out Test Set Evaluation
    test_meta = pd.read_csv(PROCESSED_DIR / "test_meta.csv")
    test_feat = pd.read_csv(PROCESSED_DIR / "test_features.csv")[FEATURE_NAMES]

    X_test = test_feat.values
    y_test = test_meta["label"].values

    probs = model.predict_proba(X_test)[:, 1]

    # Metrics at standard 0.5 threshold
    preds_50 = (probs >= 0.5).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_test, preds_50).ravel()

    # Metrics at tuned operating thresholds
    preds_sus = (probs >= sus_thresh).astype(int)
    preds_mal = (probs >= mal_thresh).astype(int)

    test_metrics = {
        "dataset_size": len(y_test),
        "legitimate_count": int((y_test == 0).sum()),
        "phishing_count": int((y_test == 1).sum()),
        "unique_domains": int(test_meta["registrable_domain"].nunique()),
        "roc_auc": float(roc_auc_score(y_test, probs)),
        "pr_auc": float(average_precision_score(y_test, probs)),
        "threshold_0_5": {
            "precision": float(precision_score(y_test, preds_50, zero_division=0)),
            "recall": float(recall_score(y_test, preds_50, zero_division=0)),
            "f1": float(f1_score(y_test, preds_50, zero_division=0)),
            "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
            "false_positive_rate": float(fp / max(tn + fp, 1)),
        },
        "suspicious_threshold": {
            "threshold": float(sus_thresh),
            "precision": float(precision_score(y_test, preds_sus, zero_division=0)),
            "recall": float(recall_score(y_test, preds_sus, zero_division=0)),
            "f1": float(f1_score(y_test, preds_sus, zero_division=0)),
        },
        "malicious_threshold": {
            "threshold": float(mal_thresh),
            "precision": float(precision_score(y_test, preds_mal, zero_division=0)),
            "recall": float(recall_score(y_test, preds_mal, zero_division=0)),
            "f1": float(f1_score(y_test, preds_mal, zero_division=0)),
        },
    }

    # Identify false positives and false negatives
    fp_indices = np.where((y_test == 0) & (preds_50 == 1))[0]
    fn_indices = np.where((y_test == 1) & (preds_50 == 0))[0]

    fp_examples = [
        {"url": str(test_meta.iloc[i]["url"]), "source": str(test_meta.iloc[i]["source"]), "score": float(probs[i])}
        for i in fp_indices[:10]
    ]
    fn_examples = [
        {"url": str(test_meta.iloc[i]["url"]), "source": str(test_meta.iloc[i]["source"]), "score": float(probs[i])}
        for i in fn_indices[:10]
    ]

    # Performance by Source
    by_source = {}
    for src, group in test_meta.groupby("source"):
        idx = group.index
        y_g = y_test[idx]
        p_g = probs[idx]
        preds_g = (p_g >= 0.5).astype(int)
        by_source[src] = {
            "count": len(y_g),
            "precision": float(precision_score(y_g, preds_g, zero_division=0)),
            "recall": float(recall_score(y_g, preds_g, zero_division=0)),
            "f1": float(f1_score(y_g, preds_g, zero_division=0)),
        }

    # Path-balanced ablation analysis
    has_path = test_meta["has_path"].values
    path_metrics = {}
    for path_cond, name in [(has_path, "urls_with_deep_path"), (~has_path, "root_urls_only")]:
        y_cond = y_test[path_cond]
        probs_cond = probs[path_cond]
        preds_cond = (probs_cond >= 0.5).astype(int)
        if len(y_cond) > 0 and len(np.unique(y_cond)) > 1:
            path_metrics[name] = {
                "count": int(len(y_cond)),
                "precision": float(precision_score(y_cond, preds_cond, zero_division=0)),
                "recall": float(recall_score(y_cond, preds_cond, zero_division=0)),
                "f1": float(f1_score(y_cond, preds_cond, zero_division=0)),
                "roc_auc": float(roc_auc_score(y_cond, probs_cond)),
            }
        else:
            path_metrics[name] = {"count": int(len(y_cond)), "note": "insufficient class diversity"}

    # 2. Real-World Sanity Set Evaluation
    sanity_meta = pd.read_csv(PROCESSED_DIR / "sanity_meta.csv")
    sanity_feat = pd.read_csv(PROCESSED_DIR / "sanity_features.csv")[FEATURE_NAMES]

    X_san = sanity_feat.values
    y_san = sanity_meta["label"].values
    probs_san = model.predict_proba(X_san)[:, 1]
    preds_san = (probs_san >= 0.5).astype(int)

    tn_s, fp_s, fn_s, tp_s = confusion_matrix(y_san, preds_san).ravel()
    legit_mask = y_san == 0
    fpr_legit = float(fp_s / max((y_san == 0).sum(), 1))

    sanity_metrics = {
        "dataset_size": len(y_san),
        "legit_count": int(legit_mask.sum()),
        "phish_count": int((y_san == 1).sum()),
        "precision": float(precision_score(y_san, preds_san, zero_division=0)),
        "recall": float(recall_score(y_san, preds_san, zero_division=0)),
        "f1": float(f1_score(y_san, preds_san, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_san, probs_san)),
        "confusion_matrix": {"tn": int(tn_s), "fp": int(fp_s), "fn": int(fn_s), "tp": int(tp_s)},
        "false_positive_rate_popular_legit": fpr_legit,
    }

    # Combined report object
    report = {
        "model_version": meta["model_version"],
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "test_set_metrics": test_metrics,
        "false_positive_examples": fp_examples,
        "false_negative_examples": fn_examples,
        "performance_by_source": by_source,
        "path_ablation": path_metrics,
        "sanity_set_metrics": sanity_metrics,
    }

    report_path = REPORTS_DIR / "url_model_metrics.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    logger.info(f"Saved evaluation metrics to {report_path}")

    # Write docs/MODEL_EVALUATION.md
    write_model_evaluation_doc(report)
    logger.info(f"Saved model evaluation documentation to {DOCS_DIR / 'MODEL_EVALUATION.md'}")
    logger.info("=== URL Threat Model Evaluation Finished Successfully ===")


def write_model_evaluation_doc(report: dict):
    m = report["test_set_metrics"]
    t05 = m["threshold_0_5"]
    ts = m["suspicious_threshold"]
    tm = m["malicious_threshold"]
    san = report["sanity_set_metrics"]
    cm = t05["confusion_matrix"]

    md = f"""# PhishShield URL Threat Model Evaluation Report

**Model Version:** `{report['model_version']}`  
**Evaluation Date:** `{report['evaluated_at']}`  
**Split Strategy:** Domain-Grouped Split (`GroupShuffleSplit` on `registrable_domain`) to strictly avoid domain leakage.

---

## 1. Held-Out Test Set Performance

The held-out test set contains **{m['dataset_size']} URLs** across **{m['unique_domains']} distinct registrable domains** ({m['legitimate_count']} legitimate, {m['phishing_count']} phishing).

| Metric | Threshold 0.50 | Suspicious Threshold ({ts['threshold']:.3f}) | Malicious Threshold ({tm['threshold']:.3f}) |
| :--- | :--- | :--- | :--- |
| **ROC-AUC** | **{m['roc_auc']:.4f}** | — | — |
| **PR-AUC** | **{m['pr_auc']:.4f}** | — | — |
| **Precision** | {t05['precision']:.4f} | {ts['precision']:.4f} | **{tm['precision']:.4f}** |
| **Recall** | {t05['recall']:.4f} | **{ts['recall']:.4f}** | {tm['recall']:.4f} |
| **F1 Score** | {t05['f1']:.4f} | {ts['f1']:.4f} | {tm['f1']:.4f} |
| **False Positive Rate** | {t05['false_positive_rate']:.4f} | — | — |

### Confusion Matrix (at threshold = 0.50)
- **True Negatives (TN):** {cm['tn']}
- **False Positives (FP):** {cm['fp']}
- **False Negatives (FN):** {cm['fn']}
- **True Positives (TP):** {cm['tp']}

---

## 2. Real-World Sanity Set Performance

A curated sanity set of **{san['dataset_size']} URLs** ({san['legit_count']} legitimate domains including bank/login portals, {san['phish_count']} recent phishing URLs) was evaluated separately:

- **ROC-AUC:** {san['roc_auc']:.4f}
- **Precision:** {san['precision']:.4f}
- **Recall:** {san['recall']:.4f}
- **F1 Score:** {san['f1']:.4f}
- **False Positive Rate on Popular Legitimate Domains:** **{san['false_positive_rate_popular_legit']:.2%}**
- **Confusion Matrix:** TN={san['confusion_matrix']['tn']}, FP={san['confusion_matrix']['fp']}, FN={san['confusion_matrix']['fn']}, TP={san['confusion_matrix']['tp']}

---

## 3. Path-Balanced Ablation

Dataset bias commonly causes models to correlate the presence of deep URL paths with phishing. We analyzed performance split by path structure:

"""
    for k, v in report.get("path_ablation", {}).items():
        if "f1" in v:
            md += f"- **{k}** ({v['count']} samples): F1={v['f1']:.4f}, Precision={v['precision']:.4f}, Recall={v['recall']:.4f}\n"
        else:
            md += f"- **{k}** ({v['count']} samples): {v.get('note', '')}\n"

    md += """
---

## 4. Performance by Dataset Source

| Source | Count | Precision | Recall | F1 Score |
| :--- | :--- | :--- | :--- | :--- |
"""
    for src, vals in report.get("performance_by_source", {}).items():
        md += f"| `{src}` | {vals['count']} | {vals['precision']:.4f} | {vals['recall']:.4f} | {vals['f1']:.4f} |\n"

    md += """
---

## 5. False Positive & False Negative Analysis

### False Positive Examples
"""
    if report["false_positive_examples"]:
        for ex in report["false_positive_examples"]:
            md += f"- `{ex['url']}` (Score: {ex['score']:.3f}, Source: {ex['source']})\n"
    else:
        md += "- None recorded on test set.\n"

    md += """
### False Negative Examples
"""
    if report["false_negative_examples"]:
        for ex in report["false_negative_examples"]:
            md += f"- `{ex['url']}` (Score: {ex['score']:.3f}, Source: {ex['source']})\n"
    else:
        md += "- None recorded on test set.\n"

    md += """
---

## 6. Honest Model Limitations

1. **Static URL-Only Input:** The model assesses lexical and structural URL patterns without accessing server content or executing JavaScript. Highly stealthy phishing sites using clean, newly registered custom domains without brand tokens may score lower.
2. **Domain Grouping Impact:** Evaluating with domain-grouped splits tests true generalisation to unseen domains. The metrics reported here reflect out-of-domain performance, avoiding artificially inflated random-split numbers.
3. **Defense-in-Depth:** In the live application, the ML score is never used in isolation; it works in tandem with deterministic brand-impersonation rules and reputation intelligence.
"""

    with open(DOCS_DIR / "MODEL_EVALUATION.md", "w", encoding="utf-8") as f:
        f.write(md)


if __name__ == "__main__":
    evaluate()

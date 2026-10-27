# PhishShield Machine Learning Pipeline

This directory contains the training and evaluation pipeline for PhishShield's URL Threat Analysis model.

---

## Scripts

1. `prepare_datasets.py`:
   - Fetches verified feeds (Tranco, URLhaus, OpenPhish) and constructs hard-negative legitimate portals and targeted kit patterns.
   - Extracts 43 lexical features with exact parity to production inference.
   - Splits data using `GroupShuffleSplit` on `registrable_domain` to prevent domain leakage.
   - Generates `reports/data_quality.json`.

2. `compare_models.py`:
   - Evaluates Logistic Regression, Random Forest, and HistGradientBoosting using 4-fold domain-grouped cross-validation.
   - Generates `reports/model_comparison.json`.

3. `train_url_model.py`:
   - Trains the production `HistGradientBoostingClassifier` with probability calibration (`CalibratedClassifierCV`).
   - Tunes operating thresholds (`suspicious_threshold`, `malicious_threshold`).
   - Saves `models/url_model.joblib` and `models/url_model_meta.json`.

4. `evaluate_url_model.py`:
   - Evaluates the model on the held-out test set and real-world sanity set.
   - Analyzes path-balanced ablation and false-positive/negative examples.
   - Generates `reports/url_model_metrics.json` and `docs/MODEL_EVALUATION.md`.

---

## Execution Command

```powershell
.\backend\.venv\Scripts\python ml\prepare_datasets.py
.\backend\.venv\Scripts\python ml\compare_models.py
.\backend\.venv\Scripts\python ml\train_url_model.py
.\backend\.venv\Scripts\python ml\evaluate_url_model.py
```

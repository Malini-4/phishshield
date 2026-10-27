# PhishShield Models Directory

- `models/url_model.joblib`: Serialized calibrated production model pipeline (`HistGradientBoostingClassifier` with `CalibratedClassifierCV`). Excluded from git.
- `models/url_model_meta.json`: Model metadata containing feature contract (`FEATURE_NAMES`), version string, dataset counts, training date, operating thresholds (`suspicious_threshold`, `malicious_threshold`), and validation metrics.

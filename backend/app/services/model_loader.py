"""
Model loader for URL threat model.
Validates FEATURE_NAMES at load time; rejects incompatible models.
"""
from __future__ import annotations

import json
import logging
from functools import lru_cache
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_MODELS_DIR = Path(__file__).parent.parent.parent.parent / "models"
_MODEL_PATH = _MODELS_DIR / "url_model.joblib"
_META_PATH = _MODELS_DIR / "url_model_meta.json"


class ModelLoadError(Exception):
    pass


class UrlModel:
    def __init__(self, pipeline, meta: dict):
        self.pipeline = pipeline
        self.meta = meta
        self.feature_names: list[str] = meta["feature_names"]
        self.malicious_threshold: float = meta["malicious_threshold"]
        self.suspicious_threshold: float = meta["suspicious_threshold"]
        self.model_version: str = meta.get("model_version", "unknown")
        self._validate_features()

    def _validate_features(self):
        """Assert feature names match current extraction code."""
        from app.security.url_features import FEATURE_NAMES
        if self.feature_names != FEATURE_NAMES:
            missing = set(FEATURE_NAMES) - set(self.feature_names)
            extra = set(self.feature_names) - set(FEATURE_NAMES)
            raise ModelLoadError(
                f"Model feature names mismatch. "
                f"Missing from model: {missing}. Extra in model: {extra}. "
                "Retrain the model with the current url_features.py."
            )
        logger.info(f"Model feature names validated ({len(self.feature_names)} features)")

    def score(self, features: dict[str, float]) -> float:
        """Return calibrated probability of phishing (0–1)."""
        from app.security.url_features import features_to_vector
        import numpy as np
        vec = features_to_vector(features)
        X = np.array(vec).reshape(1, -1)
        prob = self.pipeline.predict_proba(X)[0][1]
        return float(prob)

    def band(self, score: float) -> str:
        """Return a text band based on score vs thresholds."""
        if score >= self.malicious_threshold:
            return "high"
        elif score >= self.suspicious_threshold:
            return "medium"
        else:
            return "low"


_model_instance: Optional[UrlModel] = None
_model_load_error: Optional[str] = None
_model_tried_load: bool = False


def try_load_model() -> tuple[Optional[UrlModel], Optional[str]]:
    """
    Attempt to load the model. Returns (model, error_message).
    error_message is None on success.
    """
    global _model_instance, _model_load_error, _model_tried_load
    if _model_tried_load:
        return _model_instance, _model_load_error

    _model_tried_load = True

    if not _MODEL_PATH.exists():
        _model_load_error = (
            "Model file not found. Run 'python ml/train_url_model.py' to train the model. "
            "URL analysis will use rules and reputation checks only."
        )
        logger.warning(_model_load_error)
        return None, _model_load_error

    if not _META_PATH.exists():
        _model_load_error = "Model metadata file not found. Retrain the model."
        logger.warning(_model_load_error)
        return None, _model_load_error

    try:
        import joblib
        pipeline = joblib.load(_MODEL_PATH)
        with open(_META_PATH, encoding="utf-8") as f:
            meta = json.load(f)
        model = UrlModel(pipeline, meta)
        _model_instance = model
        _model_load_error = None
        logger.info(f"URL model loaded: version={model.model_version}, "
                    f"suspicious_threshold={model.suspicious_threshold:.3f}, "
                    f"malicious_threshold={model.malicious_threshold:.3f}")
        return model, None
    except ModelLoadError as e:
        _model_load_error = str(e)
        logger.error(f"Model incompatible: {e}")
        return None, _model_load_error
    except Exception as e:
        _model_load_error = f"Model load failed: {e}"
        logger.error(_model_load_error)
        return None, _model_load_error


def get_model() -> tuple[Optional[UrlModel], Optional[str]]:
    return try_load_model()


def model_is_loaded() -> bool:
    m, _ = try_load_model()
    return m is not None

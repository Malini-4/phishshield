"""SMS scam-language machine learning model service."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, Pipeline

from app.services.sms_text import normalise_for_model

logger = logging.getLogger(__name__)

MODEL_VERSION = "sms-lr-v1.0.0"
BASE_DIR = Path(__file__).parent.parent.parent.parent
MODEL_PATH = BASE_DIR / "models" / "sms_model.joblib"
DATASET_PATH = BASE_DIR / "data" / "sms_training" / "sms_dataset.csv"

_MODEL_PIPELINE: Optional[Any] = None


def build_pipeline() -> Pipeline:
    """Build the feature extraction and classification pipeline."""
    union = FeatureUnion([
        ("char_wb", TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), max_features=12000, sublinear_tf=True)),
        ("word", TfidfVectorizer(analyzer="word", ngram_range=(1, 2), max_features=8000, sublinear_tf=True)),
    ])
    clf = LogisticRegression(class_weight="balanced", max_iter=1000, random_state=42)
    return Pipeline([
        ("features", union),
        ("clf", clf),
    ])


def train_model(dataset_path: Path = DATASET_PATH) -> Optional[Pipeline]:
    """Train the model from the CSV dataset and save to disk."""
    if not dataset_path.exists():
        logger.warning(f"SMS dataset not found at {dataset_path}, cannot train SMS model.")
        return None

    try:
        logger.info(f"Training SMS scam language model from {dataset_path}...")
        df = pd.read_csv(dataset_path)
        if "text" not in df.columns or "label" not in df.columns:
            logger.error("Dataset missing required text or label columns.")
            return None

        # Pre-normalize text
        X = [normalise_for_model(str(t)) for t in df["text"]]
        y = df["label"].astype(int).values

        pipeline = build_pipeline()
        pipeline.fit(X, y)

        MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({
            "pipeline": pipeline,
            "version": MODEL_VERSION,
            "sklearn_version": joblib.__version__,
        }, MODEL_PATH)

        logger.info(f"Successfully trained and saved SMS model to {MODEL_PATH}")
        return pipeline
    except Exception as e:
        logger.error(f"Failed to train SMS model: {e}")
        return None


def get_model() -> Optional[Pipeline]:
    """Load the model or automatically train it if missing or corrupted."""
    global _MODEL_PIPELINE
    if _MODEL_PIPELINE is not None:
        return _MODEL_PIPELINE

    if MODEL_PATH.exists():
        try:
            data = joblib.load(MODEL_PATH)
            if isinstance(data, dict) and "pipeline" in data:
                _MODEL_PIPELINE = data["pipeline"]
                return _MODEL_PIPELINE
            elif hasattr(data, "predict_proba"):
                _MODEL_PIPELINE = data
                return _MODEL_PIPELINE
        except Exception as e:
            logger.warning(f"Failed to load cached SMS model ({e}), retraining...")

    _MODEL_PIPELINE = train_model()
    return _MODEL_PIPELINE


def predict_sms(text: str) -> Dict[str, Any]:
    """
    Predict whether an SMS message contains scam language.
    NEVER raises an exception.
    Returns:
    {
        "available": bool,
        "scam_probability": float,
        "band": str,  # 'high' | 'medium' | 'low' | 'unknown'
        "top_terms": list[str],
        "model_version": str or None,
    }
    """
    try:
        if not text or not text.strip():
            return {
                "available": True,
                "scam_probability": 0.0,
                "band": "low",
                "top_terms": [],
                "model_version": MODEL_VERSION,
            }

        model = get_model()
        if model is None:
            return {
                "available": False,
                "scam_probability": 0.0,
                "band": "unknown",
                "top_terms": [],
                "model_version": None,
            }

        norm_text = normalise_for_model(text)
        probs = model.predict_proba([norm_text])[0]
        # label 1 is scam
        scam_prob = float(probs[1])

        if scam_prob >= 0.85:
            band = "high"
        elif scam_prob >= 0.50:
            band = "medium"
        else:
            band = "low"

        # Extract top terms contributing to scam prediction
        top_terms: List[str] = []
        try:
            features = model.named_steps["features"]
            clf = model.named_steps["clf"]
            feature_names = features.get_feature_names_out()
            coefs = clf.coef_[0]

            # Transform single text to find active features
            sparse_vec = features.transform([norm_text]).tocsr()
            indices = sparse_vec.indices
            if len(indices) > 0:
                # Find indices with highest positive coefficient
                scored_terms = []
                for idx in indices:
                    score = coefs[idx] * sparse_vec[0, idx]
                    if score > 0:
                        name = feature_names[idx]
                        if "__" in name:
                            name = name.split("__", 1)[1]
                        scored_terms.append((name, score))

                scored_terms.sort(key=lambda x: x[1], reverse=True)
                top_terms = [t[0] for t in scored_terms[:5]]
        except Exception as te:
            logger.debug(f"Failed to extract top terms: {te}")

        return {
            "available": True,
            "scam_probability": round(scam_prob, 4),
            "band": band,
            "top_terms": top_terms,
            "model_version": MODEL_VERSION,
        }
    except Exception as e:
        logger.error(f"Error in predict_sms: {e}")
        return {
            "available": False,
            "scam_probability": 0.0,
            "band": "unknown",
            "top_terms": [],
            "model_version": None,
        }

"""
Model Service - manages loading, inference, and retraining of the
threat detection model.
"""
import os
import logging
import joblib
import numpy as np
from typing import Tuple
from app.core.config import settings

logger = logging.getLogger(__name__)

FEATURE_NAMES = [
    "request_count", "error_rate", "avg_response_time", "payload_size",
    "unique_ips", "failed_login_attempts", "unusual_hour_access", "geo_distance",
    "session_duration", "api_endpoint_risk_score", "token_age", "request_entropy",
    "burst_request_count", "device_risk_score", "ip_reputation_score",
    "user_behavior_deviation", "request_pattern_score", "proxy_usage_flag",
    "vpn_usage_flag", "bot_probability_score"
]

# Weights used when model file is not available
FEATURE_WEIGHTS = {
    "bot_probability_score":   0.20,
    "ip_reputation_score":     0.15,
    "user_behavior_deviation": 0.12,
    "request_pattern_score":   0.12,
    "error_rate":              0.08,
    "device_risk_score":       0.08,
    "burst_request_count":     0.07,
    "failed_login_attempts":   0.06,
    "request_entropy":         0.05,
    "api_endpoint_risk_score": 0.04,
    "proxy_usage_flag":        0.02,
    "vpn_usage_flag":          0.01,
}


class ModelService:
    def __init__(self):
        self._model = None
        self._model_version: str = "fallback-v1"
        self._using_fallback: bool = True

    def load_model(self):
        """
        Load trained model from disk on startup.
        Falls back to weighted scoring if model file not found.
        """
        path = settings.MODEL_PATH
        if os.path.exists(path):
            try:
                self._model = joblib.load(path)
                self._using_fallback = False
                self._model_version = settings.MODEL_VERSION
                logger.info(f"Model loaded from {path} (version: {self._model_version})")
            except Exception as e:
                logger.error(f"Failed to load model from {path}: {e}. Using fallback.")
                self._model = None
                self._using_fallback = True
        else:
            logger.warning(f"No model found at {path}. Using weighted scoring fallback.")
            self._model = None
            self._using_fallback = True

    def predict(self, feature_vector: list) -> Tuple[float, bool]:
        """
        Returns (probability, used_fallback).
        Tries the trained model first, falls back to weighted scoring on failure.
        """
        if self._model is not None:
            try:
                X = np.array([feature_vector])
                probability = float(self._model.predict_proba(X)[0][1])
                return round(probability, 6), False
            except Exception as e:
                logger.error(f"Model prediction failed: {e}. Using fallback.")

        return self._weighted_fallback(feature_vector), True

    def _weighted_fallback(self, features: list) -> float:
        """
        Deterministic weighted scoring used when the trained model is unavailable.
        Each feature value is multiplied by its weight and summed.
        Large counters (burst, failed logins) are normalized to 0-1 range first.
        """
        feature_dict = dict(zip(FEATURE_NAMES, features))
        score = 0.0

        for name, weight in FEATURE_WEIGHTS.items():
            value = feature_dict.get(name, 0.0)
            # Normalize large counters to 0.0-1.0
            if name == "burst_request_count":
                value = min(1.0, value / 1000.0)
            elif name == "failed_login_attempts":
                value = min(1.0, value / 50.0)
            score += value * weight

        return min(1.0, score)

    def train(self, X: np.ndarray, y: np.ndarray) -> dict:
        """
        Trains a new RandomForest pipeline and saves to disk.
        Hot-reloads the new model immediately after training.
        Returns cross-validation AUC metrics.
        """
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.preprocessing import StandardScaler
        from sklearn.pipeline import Pipeline
        from sklearn.model_selection import cross_val_score

        if len(X) < settings.MIN_TRAINING_SAMPLES:
            raise ValueError(
                f"Need at least {settings.MIN_TRAINING_SAMPLES} samples, got {len(X)}"
            )

        logger.info(f"Training model with {len(X)} samples...")

        pipeline = Pipeline([
            ("scaler", StandardScaler()),
            ("classifier", RandomForestClassifier(
                n_estimators=200,
                max_depth=12,
                min_samples_split=5,
                class_weight="balanced",  # handles imbalanced threat/safe ratio
                random_state=42,
                n_jobs=-1                 # use all CPU cores
            ))
        ])

        # 5-fold cross-validation before final fit
        cv_scores = cross_val_score(pipeline, X, y, cv=5, scoring="roc_auc")
        pipeline.fit(X, y)

        # Persist to disk
        os.makedirs(os.path.dirname(settings.MODEL_PATH), exist_ok=True)
        joblib.dump(pipeline, settings.MODEL_PATH)

        # Hot-reload — serve new model immediately, no restart needed
        self._model = pipeline
        self._using_fallback = False
        self._model_version = f"retrained-{len(X)}samples"

        metrics = {
            "cv_auc_mean": round(float(cv_scores.mean()), 4),
            "cv_auc_std":  round(float(cv_scores.std()), 4),
        }
        logger.info(
            f"Model trained. CV AUC: {metrics['cv_auc_mean']} ± {metrics['cv_auc_std']}"
        )
        return metrics

    @property
    def is_loaded(self) -> bool:
        return self._model is not None

    @property
    def is_using_fallback(self) -> bool:
        return self._using_fallback

    @property
    def model_version(self) -> str:
        return self._model_version


# Singleton — one instance shared across all requests
model_service = ModelService()
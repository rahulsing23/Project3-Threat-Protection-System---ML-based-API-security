"""
API routes for the ML threat detection service.
"""
import logging
import numpy as np
from fastapi import APIRouter, HTTPException
from app.schemas.threat_schema import (
    ThreatFeatureRequest, ThreatPredictionResponse,
    TrainingRequest, TrainingResponse, HealthResponse
)
from app.services.model_service import model_service, FEATURE_NAMES
from app.core.classifier import classify
from app.core.config import settings

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post("/predict", response_model=ThreatPredictionResponse)
def predict(request: ThreatFeatureRequest):
    """
    Main prediction endpoint — called by threat-service for every request.
    Accepts 20 ML features, returns threat probability + action.
    """
    logger.info(
        f"Prediction | ip={request.clientIp} | uri={request.requestUri} "
        f"| method={request.httpMethod}"
    )

    feature_vector = request.to_feature_vector()
    probability, used_fallback = model_service.predict(feature_vector)
    threat_level, action = classify(probability)

    if used_fallback:
        logger.info(
            f"FALLBACK | prob={probability:.4f} | level={threat_level} | action={action}"
        )
    else:
        logger.debug(
            f"ML model | prob={probability:.4f} | level={threat_level} | action={action}"
        )

    return ThreatPredictionResponse(
        threatProbability=probability,
        threatLevel=threat_level,
        action=action,
        modelVersion=model_service.model_version,
        usedFallback=used_fallback
    )


@router.post("/train", response_model=TrainingResponse)
def train(request: TrainingRequest):
    """
    Retrains the ML model with labeled data exported from threat-service PostgreSQL.

    Input format:
    {
      "samples": [
        { "features": { "request_count": 5000, "error_rate": 0.65, ... }, "label": 1 },
        { "features": { "request_count": 2,    "error_rate": 0.0,  ... }, "label": 0 }
      ]
    }
    label: 1 = confirmed threat, 0 = confirmed safe
    """
    if len(request.samples) < settings.MIN_TRAINING_SAMPLES:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Need at least {settings.MIN_TRAINING_SAMPLES} labeled samples. "
                f"Got {len(request.samples)}."
            )
        )

    # Build feature matrix and label vector
    X, y = [], []
    for sample in request.samples:
        row = [sample.features.get(f, 0.0) for f in FEATURE_NAMES]
        X.append(row)
        y.append(sample.label)

    X = np.array(X, dtype=float)
    y = np.array(y, dtype=int)

    try:
        metrics = model_service.train(X, y)
        return TrainingResponse(
            status="success",
            samples_used=len(X),
            accuracy=metrics.get("cv_auc_mean"),
            message=(
                f"Model retrained successfully. "
                f"CV AUC: {metrics.get('cv_auc_mean')} ± {metrics.get('cv_auc_std')}"
            )
        )
    except Exception as e:
        logger.error(f"Training failed: {e}")
        raise HTTPException(status_code=500, detail=f"Training failed: {str(e)}")


@router.get("/health", response_model=HealthResponse)
def health():
    """Health check — returns model load status."""
    return HealthResponse(
        status="UP",
        model_loaded=model_service.is_loaded,
        model_version=model_service.model_version,
        model_path=settings.MODEL_PATH,
        fallback_active=model_service.is_using_fallback
    )


@router.get("/model/info")
def model_info():
    """Returns model metadata and current threshold configuration."""
    return {
        "model_version":   model_service.model_version,
        "model_loaded":    model_service.is_loaded,
        "fallback_active": model_service.is_using_fallback,
        "thresholds": {
            "block":   settings.BLOCK_THRESHOLD,
            "captcha": settings.CAPTCHA_THRESHOLD,
            "monitor": settings.MONITOR_THRESHOLD,
        },
        "features":      FEATURE_NAMES,
        "feature_count": len(FEATURE_NAMES)
    }


@router.get("/")
def root():
    return {"service": "ML Threat Detection", "version": "1.0.0", "status": "running"}
"""
Application configuration loaded from environment variables.
No pydantic-settings dependency required.
"""
import os
from typing import List


class Settings:
    # Server
    HOST: str        = os.getenv("HOST", "0.0.0.0")
    PORT: int        = int(os.getenv("PORT", "8090"))
    LOG_LEVEL: str   = os.getenv("LOG_LEVEL", "INFO")

    # Model
    MODEL_PATH: str    = os.getenv("MODEL_PATH", "models/threat_model.joblib")
    MODEL_VERSION: str = os.getenv("MODEL_VERSION", "1.0.0")

    # Thresholds
    BLOCK_THRESHOLD: float   = float(os.getenv("BLOCK_THRESHOLD",   "0.80"))
    CAPTCHA_THRESHOLD: float = float(os.getenv("CAPTCHA_THRESHOLD", "0.60"))
    MONITOR_THRESHOLD: float = float(os.getenv("MONITOR_THRESHOLD", "0.40"))

    # CORS
    ALLOWED_ORIGINS: List[str] = os.getenv("ALLOWED_ORIGINS", "*").split(",")

    # Training
    MIN_TRAINING_SAMPLES: int = int(os.getenv("MIN_TRAINING_SAMPLES", "50"))


settings = Settings()

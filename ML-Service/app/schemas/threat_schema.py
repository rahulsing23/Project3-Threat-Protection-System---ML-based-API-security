"""
Pydantic schemas for ML service API.
"""
from pydantic import BaseModel, Field
from typing import Optional, List
from enum import Enum


class ThreatLevel(str, Enum):
    CRITICAL = "CRITICAL THREAT"
    HIGH     = "HIGH THREAT"
    MEDIUM   = "MEDIUM THREAT"
    LOW      = "LOW THREAT"


class ThreatAction(str, Enum):
    BLOCK   = "BLOCK"
    CAPTCHA = "CAPTCHA"
    MONITOR = "MONITOR"
    ALLOW   = "ALLOW"


class ThreatFeatureRequest(BaseModel):
    """20 ML features extracted from the incoming HTTP request."""

    # Traffic features
    request_count:           float = Field(ge=0,   description="Total requests from this IP")
    error_rate:              float = Field(ge=0.0, le=1.0)
    avg_response_time:       float = Field(ge=0)
    payload_size:            float = Field(ge=0)
    unique_ips:              int   = Field(ge=0)

    # Auth & Session
    failed_login_attempts:   int   = Field(ge=0)
    unusual_hour_access:     int   = Field(ge=0,  le=1)
    geo_distance:            float = Field(ge=0)
    session_duration:        float = Field(ge=0)
    token_age:               float = Field(ge=0)

    # Endpoint & Behavior
    api_endpoint_risk_score: float = Field(ge=0.0, le=1.0)
    request_entropy:         float = Field(ge=0.0, le=1.0)
    burst_request_count:     float = Field(ge=0)
    device_risk_score:       float = Field(ge=0.0, le=1.0)
    ip_reputation_score:     float = Field(ge=0.0, le=1.0)
    user_behavior_deviation: float = Field(ge=0.0, le=1.0)
    request_pattern_score:   float = Field(ge=0.0, le=1.0)

    # Network flags
    proxy_usage_flag:        int   = Field(ge=0,  le=1)
    vpn_usage_flag:          int   = Field(ge=0,  le=1)
    bot_probability_score:   float = Field(ge=0.0, le=1.0)

    # Metadata (not used in ML, for logging only)
    clientIp:   Optional[str] = None
    requestUri: Optional[str] = None
    httpMethod: Optional[str] = None
    userAgent:  Optional[str] = None
    sessionId:  Optional[str] = None

    def to_feature_vector(self) -> list:
        """Returns ordered list of the 20 numeric features for the model."""
        return [
            self.request_count, self.error_rate, self.avg_response_time,
            self.payload_size, self.unique_ips, self.failed_login_attempts,
            self.unusual_hour_access, self.geo_distance, self.session_duration,
            self.api_endpoint_risk_score, self.token_age, self.request_entropy,
            self.burst_request_count, self.device_risk_score, self.ip_reputation_score,
            self.user_behavior_deviation, self.request_pattern_score,
            self.proxy_usage_flag, self.vpn_usage_flag, self.bot_probability_score
        ]


class ThreatPredictionResponse(BaseModel):
    threatProbability: float
    threatLevel:       str
    action:            str
    modelVersion:      Optional[str] = None
    usedFallback:      bool = False


class TrainingSample(BaseModel):
    """Single labeled training sample."""
    features: dict
    label:    int = Field(ge=0, le=1, description="1=threat, 0=safe")


class TrainingRequest(BaseModel):
    samples: List[TrainingSample]


class TrainingResponse(BaseModel):
    status:       str
    samples_used: int
    accuracy:     Optional[float] = None
    message:      str


class HealthResponse(BaseModel):
    status:          str
    model_loaded:    bool
    model_version:   Optional[str]
    model_path:      str
    fallback_active: bool
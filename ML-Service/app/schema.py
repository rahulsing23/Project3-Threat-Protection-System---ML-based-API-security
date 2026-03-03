from pydantic import BaseModel

class AttackFeatures(BaseModel):
    request_count: float
    error_rate: float
    avg_response_time: float
    payload_size: float
    unique_ips: float
    failed_login_attempts: float
    unusual_hour_access: float
    geo_distance: float
    session_duration: float
    api_endpoint_risk_score: float
    token_age: float
    request_entropy: float
    burst_request_count: float
    device_risk_score: float
    ip_reputation_score: float
    user_behavior_deviation: float
    request_pattern_score: float
    proxy_usage_flag: float
    vpn_usage_flag: float
    bot_probability_score: float
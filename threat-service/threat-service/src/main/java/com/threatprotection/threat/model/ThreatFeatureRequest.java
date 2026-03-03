package com.threatprotection.threat.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.DecimalMax;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.Min;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ThreatFeatureRequest {

    @JsonProperty("request_count")
    @Min(0)
    private long requestCount;

    @JsonProperty("error_rate")
    @DecimalMin("0.0") @DecimalMax("1.0")
    private double errorRate;

    @JsonProperty("avg_response_time")
    private double avgResponseTime;

    @JsonProperty("payload_size")
    private long payloadSize;

    @JsonProperty("unique_ips")
    private int uniqueIps;

    @JsonProperty("failed_login_attempts")
    private int failedLoginAttempts;

    @JsonProperty("unusual_hour_access")
    private int unusualHourAccess;

    @JsonProperty("geo_distance")
    private double geoDistance;

    @JsonProperty("session_duration")
    private double sessionDuration;

    @JsonProperty("api_endpoint_risk_score")
    @DecimalMin("0.0") @DecimalMax("1.0")
    private double apiEndpointRiskScore;

    @JsonProperty("token_age")
    private double tokenAge;

    @JsonProperty("request_entropy")
    @DecimalMin("0.0") @DecimalMax("1.0")
    private double requestEntropy;

    @JsonProperty("burst_request_count")
    private long burstRequestCount;

    @JsonProperty("device_risk_score")
    @DecimalMin("0.0") @DecimalMax("1.0")
    private double deviceRiskScore;

    @JsonProperty("ip_reputation_score")
    @DecimalMin("0.0") @DecimalMax("1.0")
    private double ipReputationScore;

    @JsonProperty("user_behavior_deviation")
    @DecimalMin("0.0") @DecimalMax("1.0")
    private double userBehaviorDeviation;

    @JsonProperty("request_pattern_score")
    @DecimalMin("0.0") @DecimalMax("1.0")
    private double requestPatternScore;

    @JsonProperty("proxy_usage_flag")
    private int proxyUsageFlag;

    @JsonProperty("vpn_usage_flag")
    private int vpnUsageFlag;

    @JsonProperty("bot_probability_score")
    @DecimalMin("0.0") @DecimalMax("1.0")
    private double botProbabilityScore;

    // Metadata (not used in ML prediction, passed through for logging)
    private String clientIp;
    private String requestUri;
    private String httpMethod;
    private String userAgent;
    private String sessionId;
}
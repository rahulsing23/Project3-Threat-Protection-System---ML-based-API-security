package com.threatprotection.threat.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "threat_logs", indexes = {
        @Index(name = "idx_tl_client_ip",    columnList = "client_ip"),
        @Index(name = "idx_tl_threat_level", columnList = "threat_level"),
        @Index(name = "idx_tl_action",       columnList = "action"),
        @Index(name = "idx_tl_created_at",   columnList = "created_at"),
        @Index(name = "idx_tl_session_id",   columnList = "session_id")
})
public class ThreatLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "request_id", unique = true, length = 64)
    private String requestId;

    // ─── Metadata ─────────────────────────────────────────────────────────
    @Column(name = "client_ip",   length = 45)  private String clientIp;
    @Column(name = "request_uri", length = 500) private String requestUri;
    @Column(name = "http_method", length = 10)  private String httpMethod;
    @Column(name = "user_agent",  length = 500) private String userAgent;
    @Column(name = "session_id",  length = 255) private String sessionId;

    // ─── 20 ML Features ───────────────────────────────────────────────────
    @Column(name = "request_count")           private Long    requestCount;
    @Column(name = "error_rate")              private Double  errorRate;
    @Column(name = "avg_response_time")       private Double  avgResponseTime;
    @Column(name = "payload_size")            private Long    payloadSize;
    @Column(name = "unique_ips")              private Integer uniqueIps;
    @Column(name = "failed_login_attempts")   private Integer failedLoginAttempts;
    @Column(name = "unusual_hour_access")     private Integer unusualHourAccess;
    @Column(name = "geo_distance")            private Double  geoDistance;
    @Column(name = "session_duration")        private Double  sessionDuration;
    @Column(name = "api_endpoint_risk_score") private Double  apiEndpointRiskScore;
    @Column(name = "token_age")               private Double  tokenAge;
    @Column(name = "request_entropy")         private Double  requestEntropy;
    @Column(name = "burst_request_count")     private Long    burstRequestCount;
    @Column(name = "device_risk_score")       private Double  deviceRiskScore;
    @Column(name = "ip_reputation_score")     private Double  ipReputationScore;
    @Column(name = "user_behavior_deviation") private Double  userBehaviorDeviation;
    @Column(name = "request_pattern_score")   private Double  requestPatternScore;
    @Column(name = "proxy_usage_flag")        private Integer proxyUsageFlag;
    @Column(name = "vpn_usage_flag")          private Integer vpnUsageFlag;
    @Column(name = "bot_probability_score")   private Double  botProbabilityScore;

    // ─── ML Output ────────────────────────────────────────────────────────
    @Column(name = "threat_probability")              private Double threatProbability;
    @Column(name = "threat_level", length = 50)       private String threatLevel;
    @Column(name = "action",       length = 20)       private String action;

    // ─── Ground Truth (analyst labels for ML retraining) ─────────────────
    @Column(name = "confirmed_threat")                private Boolean confirmedThreat;
    @Column(name = "analyst_notes", length = 1000)    private String  analystNotes;
    @Column(name = "labeled_by",    length = 100)     private String  labeledBy;
    @Column(name = "labeled_at")                      private LocalDateTime labeledAt;

    // ─── Timestamps ───────────────────────────────────────────────────────
    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "evaluation_time_ms")
    private Long evaluationTimeMs;
}
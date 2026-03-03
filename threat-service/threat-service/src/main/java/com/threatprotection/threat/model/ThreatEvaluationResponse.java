package com.threatprotection.threat.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ThreatEvaluationResponse {
    private double threatProbability;
    private String threatLevel;
    private String action;
    private String message;
    private String requestId;
    private long evaluationTimeMs;
}
package com.threatprotection.gateway.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ThreatResponse {
    private double threatProbability;
    private String threatLevel;
    private String action;
    private String message;
    private String requestId;
}
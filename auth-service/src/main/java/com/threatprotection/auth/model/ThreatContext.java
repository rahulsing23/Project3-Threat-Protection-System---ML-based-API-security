package com.threatprotection.auth.model;

import jakarta.servlet.http.HttpServletRequest;
import lombok.Builder;
import lombok.Data;

/**
 * Reads the threat classification headers injected by API Gateway
 * and provides convenience methods for business logic decisions.
 *
 * Headers read:
 *   X-Request-ID          → unique request identifier
 *   X-Threat-Level        → LOW THREAT / MEDIUM THREAT / HIGH THREAT / CRITICAL THREAT
 *   X-Threat-Probability  → 0.0 - 1.0 ML score
 *   X-Threat-Action       → ALLOW / MONITOR / CAPTCHA / BLOCK
 */
@Data
@Builder
public class ThreatContext {
    private String requestId;
    private String threatLevel;
    private double threatProbability;
    private String action;

    public static ThreatContext from(HttpServletRequest request) {
        String probStr = request.getHeader("X-Threat-Probability");
        double probability = 0.0;
        try {
            if (probStr != null) probability = Double.parseDouble(probStr);
        } catch (NumberFormatException ignored) {}

        return ThreatContext.builder()
                .requestId(request.getHeader("X-Request-ID"))
                .threatLevel(request.getHeader("X-Threat-Level"))
                .threatProbability(probability)
                .action(request.getHeader("X-Threat-Action"))
                .build();
    }

    public boolean isMonitored()  { return "MONITOR".equals(action); }
    public boolean isHighThreat() {
        return "HIGH THREAT".equals(threatLevel) || "CRITICAL THREAT".equals(threatLevel);
    }
    public boolean hasContext()   { return requestId != null; }
}
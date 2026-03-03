package com.threatprotection.threat.client;

import com.threatprotection.threat.model.MlServiceResponse;
import com.threatprotection.threat.model.ThreatFeatureRequest;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import io.github.resilience4j.retry.annotation.Retry;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

/**
 * HTTP client to Python FastAPI ML Service.
 * Protected by Resilience4j Circuit Breaker + Retry.
 * Falls back to deterministic rule-based scoring on failure.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class MlServiceClient {

    private final RestTemplate mlServiceRestTemplate;

    @Value("${ml-service.url}")
    private String mlServiceUrl;

    @CircuitBreaker(name = "ml-service", fallbackMethod = "ruleBasedFallback")
    @Retry(name = "ml-service")
    public MlServiceResponse predict(ThreatFeatureRequest request) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<ThreatFeatureRequest> entity = new HttpEntity<>(request, headers);

        ResponseEntity<MlServiceResponse> response = mlServiceRestTemplate.postForEntity(
                mlServiceUrl + "/predict", entity, MlServiceResponse.class);

        if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
            log.debug("ML prediction: level={}, action={}, probability={}",
                    response.getBody().getThreatLevel(),
                    response.getBody().getAction(),
                    response.getBody().getThreatProbability());
            return response.getBody();
        }
        throw new RestClientException("Non-2xx status: " + response.getStatusCode());
    }

    // ─── Resilience4j Fallback ────────────────────────────────────────────

    @SuppressWarnings("unused")
    private MlServiceResponse ruleBasedFallback(ThreatFeatureRequest req, Throwable t) {
        log.warn("ML service fallback triggered: {}. Using rule-based scoring.", t.getMessage());
        double score = computeRuleScore(req);
        return buildResponse(score);
    }

    // ─── Deterministic Rule-Based Scoring ─────────────────────────────────

    private double computeRuleScore(ThreatFeatureRequest r) {
        double score = 0.0;

        // High-impact indicators
        if (r.getBotProbabilityScore()   > 0.8) score += 0.25;
        if (r.getIpReputationScore()     > 0.7) score += 0.20;
        if (r.getUserBehaviorDeviation() > 0.8) score += 0.15;
        if (r.getRequestPatternScore()   > 0.8) score += 0.15;
        if (r.getErrorRate()             > 0.5) score += 0.10;
        if (r.getDeviceRiskScore()       > 0.7) score += 0.10;

        // Medium-impact indicators
        if (r.getBurstRequestCount()     > 500) score += 0.08;
        if (r.getFailedLoginAttempts()   > 10)  score += 0.08;
        if (r.getRequestEntropy()        > 0.8) score += 0.05;
        if (r.getApiEndpointRiskScore()  > 0.8) score += 0.05;

        // Network flags
        if (r.getProxyUsageFlag() == 1)         score += 0.03;
        if (r.getVpnUsageFlag()   == 1)         score += 0.02;

        return Math.min(1.0, score);
    }

    private MlServiceResponse buildResponse(double probability) {
        String level, action;
        if      (probability >= 0.80) { level = "CRITICAL THREAT"; action = "BLOCK";   }
        else if (probability >= 0.60) { level = "HIGH THREAT";     action = "CAPTCHA"; }
        else if (probability >= 0.40) { level = "MEDIUM THREAT";   action = "MONITOR"; }
        else                          { level = "LOW THREAT";       action = "ALLOW";   }

        return MlServiceResponse.builder()
                .threatProbability(probability)
                .threatLevel(level)
                .action(action)
                .build();
    }
}
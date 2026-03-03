package com.threatprotection.threat.service;

import com.threatprotection.threat.client.MlServiceClient;
import com.threatprotection.threat.entity.ThreatLog;
import com.threatprotection.threat.model.MlServiceResponse;
import com.threatprotection.threat.model.ThreatEvaluationResponse;
import com.threatprotection.threat.model.ThreatFeatureRequest;
import com.threatprotection.threat.repository.ThreatLogRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class ThreatEvaluationService {

    private final MlServiceClient mlServiceClient;
    private final ThreatLogRepository threatLogRepository;
    private final IpBlacklistService ipBlacklistService;

    @Value("${threat.rules.extreme-burst-threshold:1000}")
    private long extremeBurstThreshold;

    @Value("${threat.rules.failed-login-captcha-threshold:5}")
    private int failedLoginCaptchaThreshold;

    @Value("${threat.rules.hourly-threat-escalation-count:10}")
    private long hourlyThreatEscalationCount;

    @Transactional
    public ThreatEvaluationResponse evaluate(ThreatFeatureRequest request) {
        long start = System.currentTimeMillis();
        String requestId = UUID.randomUUID().toString();

        log.info("Evaluating threat | requestId={} | ip={} | uri={}",
                requestId, request.getClientIp(), request.getRequestUri());

        // 1. ML prediction
        MlServiceResponse mlResult = mlServiceClient.predict(request);

        // 2. Business rule overrides
        MlServiceResponse finalResult = applyBusinessRules(mlResult, request);

        long evalMs = System.currentTimeMillis() - start;

        // 3. Persist all 20 features + result to PostgreSQL
        persistAsync(requestId, request, finalResult, evalMs);

        // 4. Auto-blacklist extreme threats
        autoBlacklist(finalResult, request);

        return ThreatEvaluationResponse.builder()
                .threatProbability(finalResult.getThreatProbability())
                .threatLevel(finalResult.getThreatLevel())
                .action(finalResult.getAction())
                .message(buildMessage(finalResult.getAction()))
                .requestId(requestId)
                .evaluationTimeMs(evalMs)
                .build();
    }

    // ─── Business Rules ───────────────────────────────────────────────────

    private MlServiceResponse applyBusinessRules(MlServiceResponse ml,
                                                 ThreatFeatureRequest req) {
        // Rule 1: Extreme burst → hard BLOCK regardless of ML score
        if (req.getBurstRequestCount() > extremeBurstThreshold) {
            log.warn("Extreme burst ({} req) from {} → BLOCK",
                    req.getBurstRequestCount(), req.getClientIp());
            return forceBlock(Math.max(ml.getThreatProbability(), 0.90));
        }

        // Rule 2: Trusted internal IPs → always ALLOW
        if (isTrustedInternal(req.getClientIp())) {
            return forceAllow();
        }

        // Rule 3: Too many failed logins → minimum CAPTCHA
        if (req.getFailedLoginAttempts() >= failedLoginCaptchaThreshold
                && !"BLOCK".equals(ml.getAction())) {
            log.info("Failed login threshold ({}) for {} → CAPTCHA",
                    req.getFailedLoginAttempts(), req.getClientIp());
            return forceCaptcha(Math.max(ml.getThreatProbability(), 0.61));
        }

        // Rule 4: Repeated flags in last hour → escalate ALLOW → CAPTCHA
        if ("ALLOW".equals(ml.getAction())) {
            long recentThreats = threatLogRepository.countByClientIpAndCreatedAtAfter(
                    req.getClientIp(), LocalDateTime.now().minusHours(1));
            if (recentThreats >= hourlyThreatEscalationCount) {
                log.info("IP {} flagged {} times in 1h → CAPTCHA",
                        req.getClientIp(), recentThreats);
                return forceCaptcha(Math.max(ml.getThreatProbability(), 0.62));
            }
        }

        // Rule 5: High device risk + high entropy + still ALLOW → MONITOR
        if (req.getDeviceRiskScore() > 0.85 && req.getRequestEntropy() > 0.85
                && "ALLOW".equals(ml.getAction())) {
            return forceMonitor(Math.max(ml.getThreatProbability(), 0.41));
        }

        return ml;
    }

    private void autoBlacklist(MlServiceResponse result, ThreatFeatureRequest req) {
        if ("CRITICAL THREAT".equals(result.getThreatLevel())
                && result.getThreatProbability() >= 0.95) {
            ipBlacklistService.addToBlacklist(
                    req.getClientIp(),
                    "Auto-blacklisted: probability=" + result.getThreatProbability(),
                    "system",
                    LocalDateTime.now().plusHours(24)
            );
        }
    }

    // ─── Persistence ──────────────────────────────────────────────────────

    private void persistAsync(String requestId, ThreatFeatureRequest req,
                              MlServiceResponse result, long evalMs) {
        try {
            threatLogRepository.save(ThreatLog.builder()
                    .requestId(requestId)
                    .clientIp(req.getClientIp())
                    .requestUri(req.getRequestUri())
                    .httpMethod(req.getHttpMethod())
                    .userAgent(req.getUserAgent())
                    .sessionId(req.getSessionId())
                    .requestCount(req.getRequestCount())
                    .errorRate(req.getErrorRate())
                    .avgResponseTime(req.getAvgResponseTime())
                    .payloadSize(req.getPayloadSize())
                    .uniqueIps(req.getUniqueIps())
                    .failedLoginAttempts(req.getFailedLoginAttempts())
                    .unusualHourAccess(req.getUnusualHourAccess())
                    .geoDistance(req.getGeoDistance())
                    .sessionDuration(req.getSessionDuration())
                    .apiEndpointRiskScore(req.getApiEndpointRiskScore())
                    .tokenAge(req.getTokenAge())
                    .requestEntropy(req.getRequestEntropy())
                    .burstRequestCount(req.getBurstRequestCount())
                    .deviceRiskScore(req.getDeviceRiskScore())
                    .ipReputationScore(req.getIpReputationScore())
                    .userBehaviorDeviation(req.getUserBehaviorDeviation())
                    .requestPatternScore(req.getRequestPatternScore())
                    .proxyUsageFlag(req.getProxyUsageFlag())
                    .vpnUsageFlag(req.getVpnUsageFlag())
                    .botProbabilityScore(req.getBotProbabilityScore())
                    .threatProbability(result.getThreatProbability())
                    .threatLevel(result.getThreatLevel())
                    .action(result.getAction())
                    .evaluationTimeMs(evalMs)
                    .build());
        } catch (Exception e) {
            log.error("Failed to persist threat log: {}", e.getMessage());
        }
    }

    // ─── Analytics ────────────────────────────────────────────────────────

    public Map<String, Object> getAnalytics(int hoursBack) {
        LocalDateTime since = LocalDateTime.now().minusHours(hoursBack);
        Map<String, Object> analytics = new LinkedHashMap<>();
        analytics.put("period_hours", hoursBack);
        analytics.put("since", since.toString());
        analytics.put("by_threat_level",
                toMap(threatLogRepository.countGroupedByThreatLevel(since)));
        analytics.put("by_action",
                toMap(threatLogRepository.countGroupedByAction(since)));
        analytics.put("total_blocked",
                threatLogRepository.countByActionAndCreatedAtAfter("BLOCK", since));
        analytics.put("total_captcha",
                threatLogRepository.countByActionAndCreatedAtAfter("CAPTCHA", since));
        analytics.put("top_threat_ips",
                threatLogRepository.findTopThreatIps(since, PageRequest.of(0, 10))
                        .stream()
                        .map(row -> Map.of("ip", row[0], "count", row[1]))
                        .collect(Collectors.toList()));
        return analytics;
    }

    private Map<String, Long> toMap(List<Object[]> rows) {
        return rows.stream().collect(Collectors.toMap(
                row -> String.valueOf(row[0]),
                row -> ((Number) row[1]).longValue()
        ));
    }

    // ─── Helpers ──────────────────────────────────────────────────────────

    private boolean isTrustedInternal(String ip) {
        return ip != null && (ip.startsWith("127.") || ip.startsWith("10.")
                || ip.startsWith("192.168.") || ip.equals("::1"));
    }

    private MlServiceResponse forceBlock(double prob) {
        return MlServiceResponse.builder()
                .threatProbability(prob).threatLevel("CRITICAL THREAT").action("BLOCK").build();
    }

    private MlServiceResponse forceCaptcha(double prob) {
        return MlServiceResponse.builder()
                .threatProbability(prob).threatLevel("HIGH THREAT").action("CAPTCHA").build();
    }

    private MlServiceResponse forceMonitor(double prob) {
        return MlServiceResponse.builder()
                .threatProbability(prob).threatLevel("MEDIUM THREAT").action("MONITOR").build();
    }

    private MlServiceResponse forceAllow() {
        return MlServiceResponse.builder()
                .threatProbability(0.0).threatLevel("LOW THREAT").action("ALLOW").build();
    }

    private String buildMessage(String action) {
        return switch (action) {
            case "BLOCK"   -> "Request blocked due to critical threat";
            case "CAPTCHA" -> "CAPTCHA verification required";
            case "MONITOR" -> "Request allowed under monitoring";
            default        -> "Request allowed";
        };
    }
}
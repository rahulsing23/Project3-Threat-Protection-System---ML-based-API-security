package com.threatprotection.gateway.filter;

import com.threatprotection.gateway.model.ThreatRequest;
import com.threatprotection.gateway.service.RedisCounterService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.LocalTime;
import java.util.Base64;
import java.util.Map;

/**
 * Extracts all 20 ML features from the incoming HTTP request.
 * All counters are backed by Redis — no in-memory state.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class RequestFeatureExtractor {

    private final RedisCounterService redisCounterService;

    @Value("${feature-extraction.unusual-hour-start:1}")
    private int unusualHourStart;

    @Value("${feature-extraction.unusual-hour-end:5}")
    private int unusualHourEnd;

    // Endpoint risk scoring
    private static final Map<String, Double> ENDPOINT_RISK_SCORES = Map.of(
            "/api/auth/login",    0.80,
            "/api/auth/register", 0.60,
            "/api/admin",         0.95,
            "/api/payment",       0.90,
            "/api/transfer",      0.95,
            "/api/user/delete",   0.85
    );

    /**
     * Fully reactive feature extraction using Redis for all counters.
     * All 7 Redis calls are fired in parallel via Mono.zip().
     */
    public Mono<ThreatRequest> extract(ServerHttpRequest request, long payloadSize) {
        String clientIp     = resolveClientIp(request);
        String uri          = request.getURI().getPath();
        String userAgent    = getHeader(request, "User-Agent", "");
        String sessionId    = getHeader(request, "X-Session-ID", "unknown");
        String forwardedFor = getHeader(request, "X-Forwarded-For", "");
        String proxyHeader  = getHeader(request, "Via", "");
        String authHeader   = getHeader(request, "Authorization", "");

        int proxyFlag = (!forwardedFor.isEmpty() || !proxyHeader.isEmpty()) ? 1 : 0;
        int vpnFlag   = detectVpn(clientIp) ? 1 : 0;

        // All Redis calls fired in parallel — no sequential blocking
        return Mono.zip(
                redisCounterService.incrementRequestCount(clientIp),      // t1
                redisCounterService.incrementBurstCount(clientIp),        // t2
                redisCounterService.getFailedLoginCount(clientIp),        // t3
                redisCounterService.getErrorRate(clientIp),               // t4
                redisCounterService.getUniqueIpCount(),                   // t5
                redisCounterService.getSessionDurationMinutes(sessionId), // t6
                redisCounterService.trackUniqueIp(clientIp)               // t7 (side-effect)
        ).flatMap(tuple -> {
            long   requestCount    = tuple.getT1();
            long   burstCount      = tuple.getT2();
            long   failedLogins    = tuple.getT3();
            double errorRate       = tuple.getT4();
            long   uniqueIps       = tuple.getT5();
            double sessionDuration = tuple.getT6();

            // Fire-and-forget: record session start timestamp if not already set
            redisCounterService.recordSessionStart(sessionId).subscribe();

            ThreatRequest threatRequest = ThreatRequest.builder()
                    // ── Traffic Features ──────────────────────────────────
                    .requestCount(requestCount)
                    .errorRate(errorRate)
                    .avgResponseTime(0)          // Populated by response interceptor
                    .payloadSize(payloadSize)
                    .uniqueIps((int) Math.min(uniqueIps, Integer.MAX_VALUE))

                    // ── Auth & Session Features ────────────────────────────
                    .failedLoginAttempts((int) Math.min(failedLogins, Integer.MAX_VALUE))
                    .sessionDuration(sessionDuration)
                    .tokenAge(parseTokenAgeHours(authHeader))

                    // ── Time & Geo Features ────────────────────────────────
                    .unusualHourAccess(isUnusualHour() ? 1 : 0)
                    .geoDistance(0.0)            // TODO: MaxMind GeoIP2

                    // ── Endpoint Features ──────────────────────────────────
                    .apiEndpointRiskScore(computeEndpointRiskScore(uri))

                    // ── Behavioral Features ────────────────────────────────
                    .requestEntropy(computeRequestEntropy(request))
                    .burstRequestCount(burstCount)
                    .userBehaviorDeviation(0.0)  // TODO: Behavioral baseline model
                    .requestPatternScore(computeRequestPatternScore(uri))

                    // ── Device & Network Features ──────────────────────────
                    .deviceRiskScore(computeDeviceRiskScore(userAgent))
                    .ipReputationScore(0.3)      // TODO: AbuseIPDB integration
                    .proxyUsageFlag(proxyFlag)
                    .vpnUsageFlag(vpnFlag)
                    .botProbabilityScore(computeBotProbability(userAgent, burstCount))

                    // ── Request Metadata ───────────────────────────────────
                    .clientIp(clientIp)
                    .requestUri(uri)
                    .httpMethod(request.getMethod().name())
                    .userAgent(userAgent)
                    .sessionId(sessionId)
                    .build();

            return Mono.just(threatRequest);
        });
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Feature Computation Methods
    // ─────────────────────────────────────────────────────────────────────────

    private boolean isUnusualHour() {
        int hour = LocalTime.now().getHour();
        return hour >= unusualHourStart && hour <= unusualHourEnd;
    }

    private double computeEndpointRiskScore(String uri) {
        return ENDPOINT_RISK_SCORES.entrySet().stream()
                .filter(e -> uri.startsWith(e.getKey()))
                .mapToDouble(Map.Entry::getValue)
                .max()
                .orElse(0.3); // default: medium-low risk for unknown endpoints
    }

    private double computeRequestEntropy(ServerHttpRequest request) {
        // Shannon entropy on query params.
        // High entropy = randomized parameters = likely automated/bot traffic
        String query = request.getURI().getQuery();
        if (query == null || query.isEmpty()) return 0.0;

        int[] freq = new int[128];
        for (char c : query.toCharArray()) {
            if (c < 128) freq[c]++;
        }
        double entropy = 0;
        int len = query.length();
        for (int f : freq) {
            if (f > 0) {
                double p = (double) f / len;
                entropy -= p * (Math.log(p) / Math.log(2));
            }
        }
        return Math.min(1.0, entropy / 7.0); // normalize: max Shannon entropy ≈ 7 bits
    }

    private double computeRequestPatternScore(String uri) {
        // Detects common attack signatures in the URI:
        // Path Traversal, XSS, SQL Injection, Command Injection, LFI
        String lower = uri.toLowerCase();
        double score = 0.0;

        // Path traversal
        if (lower.contains("../") || lower.contains("..\\"))
            score += 0.4;

        // XSS
        if (lower.contains("<script") || lower.contains("javascript:") || lower.contains("onerror="))
            score += 0.4;

        // SQL injection
        if (lower.contains("' or ") || lower.contains("--") || lower.contains("1=1")
                || lower.contains("union select"))
            score += 0.5;

        // Command injection
        if (lower.contains(";") && (lower.contains("cmd") || lower.contains("exec")
                || lower.contains("bash") || lower.contains("wget")))
            score += 0.5;

        // Local file inclusion
        if (lower.contains("/etc/passwd") || lower.contains("win.ini") || lower.contains("boot.ini"))
            score += 0.6;

        return Math.min(1.0, score);
    }

    private double computeDeviceRiskScore(String ua) {
        if (ua == null || ua.isEmpty()) return 0.9; // Missing UA = highly suspicious

        String lower = ua.toLowerCase();

        // Known bots / crawlers
        if (lower.contains("bot") || lower.contains("crawler") || lower.contains("spider"))
            return 0.85;

        // Scripting / automation tools
        if (lower.contains("python-requests") || lower.contains("curl/")
                || lower.contains("go-http") || lower.contains("libwww-perl"))
            return 0.65;

        // API testing tools (medium risk — legitimate devs use these too)
        if (lower.contains("postman") || lower.contains("insomnia"))
            return 0.40;

        // Normal browser (Mozilla + WebKit = real browser UA)
        if (lower.contains("mozilla") && lower.contains("webkit"))
            return 0.05;

        return 0.30; // Unknown UA pattern
    }

    private double computeBotProbability(String userAgent, long burstCount) {
        double score = 0.0;

        // Device risk contributes 40% of bot score
        score += computeDeviceRiskScore(userAgent) * 0.4;

        // High burst rate is a strong bot signal
        if (burstCount > 100) score += 0.3;
        if (burstCount > 500) score += 0.3;

        return Math.min(1.0, score);
    }

    private double parseTokenAgeHours(String authHeader) {
        // Parses the JWT "iat" (issued-at) claim from the Bearer token
        // and returns how many hours old the token is.
        if (authHeader == null || !authHeader.startsWith("Bearer ")) return 0.0;
        try {
            String token = authHeader.substring(7);
            String[] parts = token.split("\\.");
            if (parts.length < 2) return 0.0;

            // Base64URL decode the payload (2nd part of JWT)
            String payload = new String(Base64.getUrlDecoder().decode(parts[1]));

            int iatIdx = payload.indexOf("\"iat\":");
            if (iatIdx < 0) return 0.0;

            // Extract the numeric value after "iat":
            String sub = payload.substring(iatIdx + 6).replaceAll("[^0-9].*", "");
            long iat = Long.parseLong(sub);

            return (System.currentTimeMillis() / 1000.0 - iat) / 3600.0;
        } catch (Exception e) {
            return 0.0;
        }
    }

    private boolean detectVpn(String ip) {
        // Heuristic check against known datacenter/proxy IP prefixes.
        // TODO: Replace with IPinfo.io or ip-api.com API call for accuracy.
        return ip != null && (
                ip.startsWith("104.") ||   // Cloudflare CDN range
                        ip.startsWith("172.16.") ||
                        ip.startsWith("100.")
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // IP Resolution
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Resolves the real client IP, respecting standard proxy headers in priority order:
     * CF-Connecting-IP (Cloudflare) > X-Forwarded-For > X-Real-IP > socket address
     */
    public String resolveClientIp(ServerHttpRequest request) {
        // Cloudflare — most authoritative if you're behind CF
        String cfIp = getHeader(request, "CF-Connecting-IP", "");
        if (!cfIp.isEmpty()) return cfIp;

        // Standard load balancer / reverse proxy header
        String xff = getHeader(request, "X-Forwarded-For", "");
        if (!xff.isEmpty()) return xff.split(",")[0].trim();

        // Nginx proxy
        String xri = getHeader(request, "X-Real-IP", "");
        if (!xri.isEmpty()) return xri;

        // Direct socket connection (no proxy)
        if (request.getRemoteAddress() != null) {
            return request.getRemoteAddress().getAddress().getHostAddress();
        }

        return "unknown";
    }

    private String getHeader(ServerHttpRequest req, String name, String defaultValue) {
        String value = req.getHeaders().getFirst(name);
        return value != null ? value : defaultValue;
    }
}
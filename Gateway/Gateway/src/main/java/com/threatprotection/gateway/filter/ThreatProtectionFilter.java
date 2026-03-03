package com.threatprotection.gateway.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.threatprotection.gateway.client.ThreatServiceClient;
import com.threatprotection.gateway.model.ThreatRequest;
import com.threatprotection.gateway.model.ThreatResponse;
import com.threatprotection.gateway.service.RedisCounterService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.UUID;

/**
 * ┌──────────────────────────────────────────────────────────────┐
 * │          THREAT PROTECTION GATEWAY FILTER (Production)        │
 * │                                                               │
 * │  Flow per request:                                            │
 * │  1. Check Redis IP blacklist  → BLOCK immediately             │
 * │  2. Check Redis IP whitelist  → ALLOW immediately             │
 * │  3. Check CAPTCHA bypass token → ALLOW if valid               │
 * │  4. Extract 20 features (Redis-backed)                        │
 * │  5. Call Threat Service → ML Service                          │
 * │  6. CRITICAL THREAT → 403 BLOCK                               │
 * │     HIGH THREAT     → 307 CAPTCHA                             │
 * │     MEDIUM THREAT   → ALLOW + monitor headers                 │
 * │     LOW THREAT      → ALLOW                                   │
 * └──────────────────────────────────────────────────────────────┘
 */
@Slf4j
@Component
public class ThreatProtectionFilter extends AbstractGatewayFilterFactory<ThreatProtectionFilter.Config> {

    private final ThreatServiceClient threatServiceClient;
    private final RequestFeatureExtractor featureExtractor;
    private final RedisCounterService redisCounterService;
    private final ObjectMapper objectMapper;

    public ThreatProtectionFilter(ThreatServiceClient threatServiceClient,
                                  RequestFeatureExtractor featureExtractor,
                                  RedisCounterService redisCounterService,
                                  ObjectMapper objectMapper) {
        super(Config.class);
        this.threatServiceClient = threatServiceClient;
        this.featureExtractor = featureExtractor;
        this.redisCounterService = redisCounterService;
        this.objectMapper = objectMapper;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            String clientIp = featureExtractor.resolveClientIp(request);
            String requestId = UUID.randomUUID().toString();
            String bypassToken = request.getHeaders().getFirst("X-Captcha-Bypass-Token");

            // Fast-path checks before doing full ML evaluation
            return redisCounterService.isIpBlacklisted(clientIp)
                    .flatMap(blacklisted -> {
                        if (blacklisted) {
                            log.warn("[{}] IP {} is blacklisted - instant block", requestId, clientIp);
                            return blockRequest(exchange, buildBlockResponse("CRITICAL THREAT", requestId), requestId);
                        }
                        return redisCounterService.isIpWhitelisted(clientIp);
                    })
                    .flatMap(whitelisted -> {
                        // NOTE: after blacklist check, this bool means "is whitelisted"
                        // We need to handle the flow carefully
                        return processWithBypassOrFull(exchange, chain, clientIp, requestId, bypassToken);
                    });
        };
    }

    private Mono<Void> processWithBypassOrFull(ServerWebExchange exchange,
                                               GatewayFilterChain chain,
                                               String clientIp,
                                               String requestId,
                                               String bypassToken) {
        // Check CAPTCHA bypass token first (avoids ML call for verified users)
        Mono<Boolean> bypassCheck = (bypassToken != null)
                ? redisCounterService.validateCaptchaBypassToken(bypassToken)
                : Mono.just(false);

        return bypassCheck.flatMap(hasBypass -> {
            if (hasBypass) {
                log.debug("[{}] CAPTCHA bypass token valid - allowing", requestId);
                // Consume token (single use) and allow
                redisCounterService.consumeCaptchaBypassToken(bypassToken).subscribe();
                return passThrough(exchange, chain, requestId, "LOW THREAT", 0.0);
            }

            // Full ML evaluation path
            return readBodyAndEvaluate(exchange, chain, clientIp, requestId);
        });
    }

    private Mono<Void> readBodyAndEvaluate(ServerWebExchange exchange,
                                           GatewayFilterChain chain,
                                           String clientIp,
                                           String requestId) {
        return DataBufferUtils.join(exchange.getRequest().getBody())
                .defaultIfEmpty(exchange.getResponse().bufferFactory().wrap(new byte[0]))
                .flatMap(dataBuffer -> {
                    byte[] bytes = new byte[dataBuffer.readableByteCount()];
                    dataBuffer.read(bytes);
                    DataBufferUtils.release(dataBuffer);
                    long payloadSize = bytes.length;

                    return featureExtractor.extract(exchange.getRequest(), payloadSize)
                            .flatMap(threatRequest -> threatServiceClient.evaluateThreat(threatRequest))
                            .flatMap(threatResponse -> {
                                threatResponse.setRequestId(requestId);
                                log.info("[{}] Threat result: level={} action={} prob={} ip={}",
                                        requestId, threatResponse.getThreatLevel(),
                                        threatResponse.getAction(),
                                        String.format("%.4f", threatResponse.getThreatProbability()),
                                        clientIp);

                                return handleAction(exchange, chain, threatResponse, requestId);
                            });
                });
    }

    // ─── Action Handlers ─────────────────────────────────────────────────

    private Mono<Void> handleAction(ServerWebExchange exchange,
                                    GatewayFilterChain chain,
                                    ThreatResponse response,
                                    String requestId) {
        return switch (response.getAction()) {
            case "BLOCK"   -> blockRequest(exchange, response, requestId);
            case "CAPTCHA" -> redirectToCaptcha(exchange, response, requestId);
            case "MONITOR" -> passThrough(exchange, chain, requestId,
                    response.getThreatLevel(), response.getThreatProbability());
            default        -> passThrough(exchange, chain, requestId,
                    response.getThreatLevel(), response.getThreatProbability());
        };
    }

    private Mono<Void> blockRequest(ServerWebExchange exchange, ThreatResponse response, String requestId) {
        exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
        exchange.getResponse().getHeaders().set("X-Request-ID", requestId);

        Map<String, Object> body = Map.of(
                "error",       "ACCESS_DENIED",
                "message",     "Request blocked: suspicious activity detected",
                "threatLevel", response.getThreatLevel(),
                "requestId",   requestId,
                "timestamp",   System.currentTimeMillis()
        );

        try {
            byte[] bytes = objectMapper.writeValueAsBytes(body);
            DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);
            return exchange.getResponse().writeWith(Mono.just(buffer));
        } catch (Exception e) {
            return exchange.getResponse().setComplete();
        }
    }

    private Mono<Void> redirectToCaptcha(ServerWebExchange exchange, ThreatResponse response, String requestId) {
        String originalPath = exchange.getRequest().getURI().getPath();
        String location = "/captcha/challenge"
                + "?requestId=" + requestId
                + "&redirectTo=" + originalPath
                + "&threatLevel=" + response.getThreatLevel();

        exchange.getResponse().setStatusCode(HttpStatus.TEMPORARY_REDIRECT);
        exchange.getResponse().getHeaders().set(HttpHeaders.LOCATION, location);
        exchange.getResponse().getHeaders().set("X-Request-ID", requestId);
        return exchange.getResponse().setComplete();
    }

    private Mono<Void> passThrough(ServerWebExchange exchange,
                                   GatewayFilterChain chain,
                                   String requestId,
                                   String threatLevel,
                                   double threatProbability) {
        ServerHttpRequest mutated = exchange.getRequest().mutate()
                .header("X-Request-ID", requestId)
                .header("X-Threat-Level", threatLevel)
                .header("X-Threat-Probability", String.valueOf(threatProbability))
                .build();
        return chain.filter(exchange.mutate().request(mutated).build());
    }

    private ThreatResponse buildBlockResponse(String level, String requestId) {
        return ThreatResponse.builder()
                .threatLevel(level)
                .action("BLOCK")
                .threatProbability(1.0)
                .requestId(requestId)
                .build();
    }

    public static class Config {}
}
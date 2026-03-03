package com.threatprotection.gateway.client;

import com.threatprotection.gateway.model.ThreatRequest;
import com.threatprotection.gateway.model.ThreatResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.time.Duration;

@Slf4j
@Component
@RequiredArgsConstructor
public class ThreatServiceClient {

    private final WebClient threatServiceWebClient;

    @Value("${threat-service.timeout-ms:5000}")
    private long timeoutMs;

    @Value("${threat-service.fallback-action:ALLOW}")
    private String fallbackAction;

    public Mono<ThreatResponse> evaluateThreat(ThreatRequest request) {
        return threatServiceWebClient.post()
                .uri("/threat/evaluate")
                .bodyValue(request)
                .retrieve()
                .bodyToMono(ThreatResponse.class)
                .timeout(Duration.ofMillis(timeoutMs))
                .doOnError(e -> log.error("Threat service call failed: {}", e.getMessage()))
                .onErrorReturn(buildFallbackResponse());
    }

    private ThreatResponse buildFallbackResponse() {
        log.warn("Using fallback threat response: action={}", fallbackAction);
        return ThreatResponse.builder()
                .threatLevel("UNKNOWN")
                .action(fallbackAction)
                .threatProbability(0.0)
                .message("Threat service unavailable")
                .build();
    }
}
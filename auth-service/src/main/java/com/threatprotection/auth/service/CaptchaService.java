package com.threatprotection.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;
import java.util.Map;
import java.util.UUID;

/**
 * Handles Google reCAPTCHA v2 verification and Redis-backed bypass tokens.
 *
 * Redis key pattern:  auth:bypass:{token} → requestId  (TTL = 5 min)
 *
 * Flow:
 *   1. User gets redirected to /captcha/challenge by API Gateway
 *   2. User solves CAPTCHA, POST /captcha/verify is called
 *   3. CaptchaService verifies token with Google, issues bypass token
 *   4. Frontend adds X-Captcha-Bypass-Token header to retry request
 *   5. API Gateway reads bypass token from Redis, skips ML evaluation
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class CaptchaService {

    private final StringRedisTemplate redisTemplate;
    private final RestTemplate restTemplate;

    @Value("${captcha.secret-key}")
    private String secretKey;

    @Value("${captcha.verify-url}")
    private String verifyUrl;

    @Value("${captcha.bypass-token-ttl-seconds:300}")
    private long bypassTokenTtl;

    private static final String BYPASS_PREFIX = "auth:bypass:";

    /**
     * Verifies a reCAPTCHA response token with Google's API.
     */
    public boolean verify(String captchaResponse) {
        if (captchaResponse == null || captchaResponse.isBlank()) {
            log.warn("Empty CAPTCHA token received");
            return false;
        }
        try {
            String url = verifyUrl + "?secret=" + secretKey + "&response=" + captchaResponse;
            ResponseEntity<Map> response = restTemplate.postForEntity(url, null, Map.class);
            boolean success = response.getStatusCode().is2xxSuccessful()
                    && response.getBody() != null
                    && Boolean.TRUE.equals(response.getBody().get("success"));
            log.info("CAPTCHA verification result: {}", success);
            return success;
        } catch (Exception e) {
            log.error("CAPTCHA verification error: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Issues a single-use Redis bypass token after successful CAPTCHA verification.
     * The API Gateway will consume and delete this token on the next request.
     */
    public String issueBypassToken(String requestId) {
        String token = UUID.randomUUID().toString();
        String key = BYPASS_PREFIX + token;
        redisTemplate.opsForValue().set(key, requestId, Duration.ofSeconds(bypassTokenTtl));
        log.info("Issued bypass token for requestId={}", requestId);
        return token;
    }

    /**
     * Validates a bypass token exists in Redis.
     */
    public boolean validateBypassToken(String token) {
        if (token == null) return false;
        return Boolean.TRUE.equals(redisTemplate.hasKey(BYPASS_PREFIX + token));
    }
}
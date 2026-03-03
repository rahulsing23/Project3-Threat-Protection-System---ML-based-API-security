package com.threatprotection.gateway.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Duration;

/**
 * Production Redis-backed counter service.
 *
 * Redis Key Strategy:
 *   gateway:req:{ip}          → total request count per IP
 *   gateway:burst:{ip}        → burst count (10s sliding window)
 *   gateway:err:{ip}          → error count (5min window)
 *   gateway:login_fail:{ip}   → failed login count (30min window)
 *   gateway:unique_ips        → HyperLogLog for unique IP estimation
 *   gateway:session:{sid}     → session start timestamp
 *   gateway:bypass:{token}    → captcha bypass token
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RedisCounterService {

    private final ReactiveStringRedisTemplate redisTemplate;

    @Value("${redis.ttl.request-counter:3600}")
    private long requestCounterTtl;

    @Value("${redis.ttl.burst-counter:10}")
    private long burstCounterTtl;

    @Value("${redis.ttl.failed-login:1800}")
    private long failedLoginTtl;

    @Value("${redis.ttl.error-counter:300}")
    private long errorCounterTtl;

    @Value("${redis.ttl.bypass-token:300}")
    private long bypassTokenTtl;

    private static final String PREFIX = "gateway:";

    // ─── Request Counter ──────────────────────────────────────────────────

    public Mono<Long> incrementRequestCount(String ip) {
        String key = PREFIX + "req:" + ip;
        return redisTemplate.opsForValue().increment(key)
                .flatMap(count -> {
                    if (count == 1) {
                        // First request — set expiry
                        return redisTemplate.expire(key, Duration.ofSeconds(requestCounterTtl))
                                .thenReturn(count);
                    }
                    return Mono.just(count);
                })
                .onErrorReturn(0L);
    }

    public Mono<Long> getRequestCount(String ip) {
        return redisTemplate.opsForValue().get(PREFIX + "req:" + ip)
                .map(Long::parseLong)
                .defaultIfEmpty(0L)
                .onErrorReturn(0L);
    }

    // ─── Burst Counter (short TTL sliding window) ─────────────────────────

    public Mono<Long> incrementBurstCount(String ip) {
        String key = PREFIX + "burst:" + ip;
        return redisTemplate.opsForValue().increment(key)
                .flatMap(count -> {
                    if (count == 1) {
                        return redisTemplate.expire(key, Duration.ofSeconds(burstCounterTtl))
                                .thenReturn(count);
                    }
                    return Mono.just(count);
                })
                .onErrorReturn(0L);
    }

    public Mono<Long> getBurstCount(String ip) {
        return redisTemplate.opsForValue().get(PREFIX + "burst:" + ip)
                .map(Long::parseLong)
                .defaultIfEmpty(0L)
                .onErrorReturn(0L);
    }

    // ─── Failed Login Counter ─────────────────────────────────────────────

    public Mono<Long> incrementFailedLogin(String ip) {
        String key = PREFIX + "login_fail:" + ip;
        return redisTemplate.opsForValue().increment(key)
                .flatMap(count -> {
                    if (count == 1) {
                        return redisTemplate.expire(key, Duration.ofSeconds(failedLoginTtl))
                                .thenReturn(count);
                    }
                    return Mono.just(count);
                })
                .onErrorReturn(0L);
    }

    public Mono<Long> getFailedLoginCount(String ip) {
        return redisTemplate.opsForValue().get(PREFIX + "login_fail:" + ip)
                .map(Long::parseLong)
                .defaultIfEmpty(0L)
                .onErrorReturn(0L);
    }

    // ─── Error Counter (5-min window) ─────────────────────────────────────

    public Mono<Long> incrementErrorCount(String ip) {
        String key = PREFIX + "err:" + ip;
        return redisTemplate.opsForValue().increment(key)
                .flatMap(count -> {
                    if (count == 1) {
                        return redisTemplate.expire(key, Duration.ofSeconds(errorCounterTtl))
                                .thenReturn(count);
                    }
                    return Mono.just(count);
                })
                .onErrorReturn(0L);
    }

    public Mono<Double> getErrorRate(String ip) {
        String errKey = PREFIX + "err:" + ip;
        String reqKey = PREFIX + "req:" + ip;

        return Mono.zip(
                redisTemplate.opsForValue().get(errKey).map(Long::parseLong).defaultIfEmpty(0L),
                redisTemplate.opsForValue().get(reqKey).map(Long::parseLong).defaultIfEmpty(0L)
        ).map(tuple -> {
            long errors = tuple.getT1();
            long total = tuple.getT2();
            if (total == 0) return 0.0;
            return Math.min(1.0, (double) errors / total);
        }).onErrorReturn(0.0);
    }

    // ─── Unique IPs (HyperLogLog) ─────────────────────────────────────────

    public Mono<Long> trackUniqueIp(String ip) {
        String key = PREFIX + "unique_ips";
        return redisTemplate.opsForHyperLogLog().add(key, ip)
                .onErrorReturn(0L);
    }

    public Mono<Long> getUniqueIpCount() {
        return redisTemplate.opsForHyperLogLog().size(PREFIX + "unique_ips")
                .defaultIfEmpty(0L)
                .onErrorReturn(0L);
    }

    // ─── Session Duration ─────────────────────────────────────────────────

    public Mono<Void> recordSessionStart(String sessionId) {
        String key = PREFIX + "session:" + sessionId;
        return redisTemplate.opsForValue()
                .setIfAbsent(key, String.valueOf(System.currentTimeMillis()),
                        Duration.ofHours(24))
                .then();
    }

    public Mono<Double> getSessionDurationMinutes(String sessionId) {
        if (sessionId == null || sessionId.equals("unknown")) return Mono.just(0.0);
        return redisTemplate.opsForValue().get(PREFIX + "session:" + sessionId)
                .map(startTimeStr -> {
                    long startTime = Long.parseLong(startTimeStr);
                    return (System.currentTimeMillis() - startTime) / 60000.0;
                })
                .defaultIfEmpty(0.0)
                .onErrorReturn(0.0);
    }

    // ─── Captcha Bypass Tokens ────────────────────────────────────────────

    public Mono<Void> storeCaptchaBypassToken(String token) {
        return redisTemplate.opsForValue()
                .set(PREFIX + "bypass:" + token, "valid", Duration.ofSeconds(bypassTokenTtl))
                .then();
    }

    public Mono<Boolean> validateCaptchaBypassToken(String token) {
        if (token == null) return Mono.just(false);
        return redisTemplate.hasKey(PREFIX + "bypass:" + token)
                .defaultIfEmpty(false)
                .onErrorReturn(false);
    }

    public Mono<Boolean> consumeCaptchaBypassToken(String token) {
        return redisTemplate.delete(PREFIX + "bypass:" + token)
                .map(deleted -> deleted > 0)
                .defaultIfEmpty(false);
    }

    // ─── IP Blacklist ─────────────────────────────────────────────────────

    public Mono<Boolean> isIpBlacklisted(String ip) {
        return redisTemplate.opsForSet().isMember(PREFIX + "blacklist", ip)
                .defaultIfEmpty(false)
                .onErrorReturn(false);
    }

    public Mono<Long> addToBlacklist(String ip) {
        return redisTemplate.opsForSet().add(PREFIX + "blacklist", ip)
                .onErrorReturn(0L);
    }

    // ─── Whitelist ────────────────────────────────────────────────────────

    public Mono<Boolean> isIpWhitelisted(String ip) {
        return redisTemplate.opsForSet().isMember(PREFIX + "whitelist", ip)
                .defaultIfEmpty(false)
                .onErrorReturn(false);
    }
}
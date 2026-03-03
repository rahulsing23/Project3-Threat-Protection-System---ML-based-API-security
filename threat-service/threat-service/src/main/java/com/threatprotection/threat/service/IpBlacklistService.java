package com.threatprotection.threat.service;

import com.threatprotection.threat.entity.IpBlacklist;
import com.threatprotection.threat.repository.IpBlacklistRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Manages IP blacklist with two layers:
 *   1. PostgreSQL — source of truth, persisted across restarts
 *   2. Redis SET  — fast lookup cache, synced from DB every 5 minutes
 *
 * Gateway reads Redis directly for low-latency; this service keeps Redis warm.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class IpBlacklistService {

    private final IpBlacklistRepository blacklistRepository;
    private final StringRedisTemplate redisTemplate;

    private static final String REDIS_BLACKLIST_KEY = "gateway:blacklist";
    private static final String REDIS_WHITELIST_KEY = "gateway:whitelist";

    // ─── Scheduled DB → Redis Sync ────────────────────────────────────────

    @Scheduled(cron = "${scheduler.blacklist-sync-cron:0 */5 * * * *}")
    @Transactional(readOnly = true)
    public void syncBlacklistToRedis() {
        try {
            List<IpBlacklist> active =
                    blacklistRepository.findAllActiveAndNotExpired(LocalDateTime.now());

            // Atomic clear + repopulate
            redisTemplate.delete(REDIS_BLACKLIST_KEY);
            if (!active.isEmpty()) {
                String[] ips = active.stream()
                        .map(IpBlacklist::getIpAddress)
                        .toArray(String[]::new);
                redisTemplate.opsForSet().add(REDIS_BLACKLIST_KEY, ips);
            }

            expireOldEntries();
            log.debug("Synced {} blacklisted IPs to Redis", active.size());
        } catch (Exception e) {
            log.error("Failed to sync blacklist to Redis: {}", e.getMessage());
        }
    }

    // ─── CRUD ─────────────────────────────────────────────────────────────

    @Transactional
    public IpBlacklist addToBlacklist(String ip, String reason,
                                      String addedBy, LocalDateTime expiresAt) {
        IpBlacklist entry = IpBlacklist.builder()
                .ipAddress(ip)
                .reason(reason)
                .addedBy(addedBy)
                .expiresAt(expiresAt)
                .active(true)
                .build();
        IpBlacklist saved = blacklistRepository.save(entry);

        // Immediately propagate to Redis — don't wait for next scheduled sync
        redisTemplate.opsForSet().add(REDIS_BLACKLIST_KEY, ip);
        log.info("IP {} blacklisted by {}: {}", ip, addedBy, reason);
        return saved;
    }

    @Transactional
    public void removeFromBlacklist(String ip) {
        blacklistRepository.findByIpAddressAndActiveTrue(ip).ifPresent(entry -> {
            entry.setActive(false);
            blacklistRepository.save(entry);
        });
        redisTemplate.opsForSet().remove(REDIS_BLACKLIST_KEY, ip);
        log.info("IP {} removed from blacklist", ip);
    }

    public boolean isBlacklisted(String ip) {
        Boolean result = redisTemplate.opsForSet().isMember(REDIS_BLACKLIST_KEY, ip);
        return Boolean.TRUE.equals(result);
    }

    @Transactional
    public void addToWhitelist(String ip) {
        redisTemplate.opsForSet().add(REDIS_WHITELIST_KEY, ip);
        log.info("IP {} added to whitelist", ip);
    }

    // ─── Internal ─────────────────────────────────────────────────────────

    private void expireOldEntries() {
        List<IpBlacklist> expired = blacklistRepository.findExpired(LocalDateTime.now());
        expired.forEach(e -> e.setActive(false));
        if (!expired.isEmpty()) {
            blacklistRepository.saveAll(expired);
            log.info("Expired {} blacklist entries", expired.size());
        }
    }
}
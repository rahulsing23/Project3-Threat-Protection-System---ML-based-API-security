package com.threatprotection.threat.repository;

import com.threatprotection.threat.entity.ThreatLog;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface ThreatLogRepository extends JpaRepository<ThreatLog, Long> {

    Optional<ThreatLog> findByRequestId(String requestId);

    Page<ThreatLog> findByClientIpOrderByCreatedAtDesc(String clientIp, Pageable pageable);

    Page<ThreatLog> findByThreatLevelOrderByCreatedAtDesc(String threatLevel, Pageable pageable);

    long countByClientIpAndCreatedAtAfter(String clientIp, LocalDateTime since);

    long countByActionAndCreatedAtAfter(String action, LocalDateTime since);

    // ─── Analytics ────────────────────────────────────────────────────────

    @Query("SELECT t.threatLevel, COUNT(t) FROM ThreatLog t " +
            "WHERE t.createdAt >= :since GROUP BY t.threatLevel ORDER BY COUNT(t) DESC")
    List<Object[]> countGroupedByThreatLevel(@Param("since") LocalDateTime since);

    @Query("SELECT t.action, COUNT(t) FROM ThreatLog t " +
            "WHERE t.createdAt >= :since GROUP BY t.action")
    List<Object[]> countGroupedByAction(@Param("since") LocalDateTime since);

    @Query("SELECT t.clientIp, COUNT(t) as cnt FROM ThreatLog t " +
            "WHERE t.createdAt >= :since AND t.action IN ('BLOCK','CAPTCHA') " +
            "GROUP BY t.clientIp ORDER BY cnt DESC")
    List<Object[]> findTopThreatIps(@Param("since") LocalDateTime since, Pageable pageable);

    // ─── ML Retraining Export ─────────────────────────────────────────────

    @Query("SELECT t FROM ThreatLog t WHERE t.confirmedThreat IS NOT NULL " +
            "ORDER BY t.createdAt DESC")
    List<ThreatLog> findLabeledForRetraining();

    @Query("SELECT t FROM ThreatLog t WHERE t.confirmedThreat IS NOT NULL " +
            "AND t.createdAt >= :since ORDER BY t.createdAt DESC")
    List<ThreatLog> findLabeledSince(@Param("since") LocalDateTime since);
}
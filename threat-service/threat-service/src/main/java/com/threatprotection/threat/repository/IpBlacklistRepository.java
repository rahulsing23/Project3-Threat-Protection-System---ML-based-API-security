package com.threatprotection.threat.repository;

import com.threatprotection.threat.entity.IpBlacklist;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface IpBlacklistRepository extends JpaRepository<IpBlacklist, Long> {

    Optional<IpBlacklist> findByIpAddressAndActiveTrue(String ipAddress);

    boolean existsByIpAddressAndActiveTrue(String ipAddress);

    @Query("SELECT b FROM IpBlacklist b WHERE b.active = true " +
            "AND (b.expiresAt IS NULL OR b.expiresAt > :now)")
    List<IpBlacklist> findAllActiveAndNotExpired(@Param("now") LocalDateTime now);

    @Query("SELECT b FROM IpBlacklist b WHERE b.active = true AND b.expiresAt <= :now")
    List<IpBlacklist> findExpired(@Param("now") LocalDateTime now);
}
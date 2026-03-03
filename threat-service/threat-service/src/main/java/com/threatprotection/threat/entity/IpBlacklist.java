package com.threatprotection.threat.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "ip_blacklist", indexes = {
        @Index(name = "idx_bl_ip", columnList = "ip_address", unique = true)
})
public class IpBlacklist {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "ip_address", unique = true, nullable = false, length = 45)
    private String ipAddress;

    @Column(name = "reason", length = 500)
    private String reason;

    @Column(name = "added_by", length = 100)
    private String addedBy;

    @Column(name = "expires_at")
    private LocalDateTime expiresAt;    // null = permanent ban

    @Column(name = "active")
    private boolean active = true;

    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;
}
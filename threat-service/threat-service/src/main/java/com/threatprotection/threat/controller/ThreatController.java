package com.threatprotection.threat.controller;

import com.threatprotection.threat.model.ThreatEvaluationResponse;
import com.threatprotection.threat.model.ThreatFeatureRequest;
import com.threatprotection.threat.service.IpBlacklistService;
import com.threatprotection.threat.service.ThreatEvaluationService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/threat")
@RequiredArgsConstructor
public class ThreatController {

    private final ThreatEvaluationService threatEvaluationService;
    private final IpBlacklistService ipBlacklistService;

    /** Called by API Gateway for every incoming request */
    @PostMapping("/evaluate")
    public ResponseEntity<ThreatEvaluationResponse> evaluate(
            @Valid @RequestBody ThreatFeatureRequest request) {
        return ResponseEntity.ok(threatEvaluationService.evaluate(request));
    }

    /** Analytics dashboard */
    @GetMapping("/analytics")
    public ResponseEntity<Map<String, Object>> analytics(
            @RequestParam(defaultValue = "24") int hours) {
        return ResponseEntity.ok(threatEvaluationService.getAnalytics(hours));
    }

    /** Add IP to blacklist */
    @PostMapping("/blacklist/{ip}")
    public ResponseEntity<Map<String, String>> blacklist(
            @PathVariable String ip,
            @RequestParam(defaultValue = "Manual block") String reason,
            @RequestParam(defaultValue = "admin") String addedBy,
            @RequestParam(required = false) Integer expireHours) {
        LocalDateTime expiresAt = expireHours != null
                ? LocalDateTime.now().plusHours(expireHours) : null;
        ipBlacklistService.addToBlacklist(ip, reason, addedBy, expiresAt);
        return ResponseEntity.ok(Map.of("status", "blacklisted", "ip", ip));
    }

    /** Remove IP from blacklist */
    @DeleteMapping("/blacklist/{ip}")
    public ResponseEntity<Map<String, String>> removeBlacklist(@PathVariable String ip) {
        ipBlacklistService.removeFromBlacklist(ip);
        return ResponseEntity.ok(Map.of("status", "removed", "ip", ip));
    }

    /** Health check */
    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> health() {
        return ResponseEntity.ok(Map.of("status", "UP", "service", "threat-service"));
    }
}
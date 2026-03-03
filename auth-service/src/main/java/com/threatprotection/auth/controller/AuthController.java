package com.threatprotection.auth.controller;

import com.threatprotection.auth.model.LoginRequest;
import com.threatprotection.auth.model.ThreatContext;
import com.threatprotection.auth.service.CaptchaService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@Slf4j
@RestController
@RequiredArgsConstructor
public class AuthController {

    private final CaptchaService captchaService;

    // ─── Auth Endpoints ───────────────────────────────────────────────────

    /**
     * POST /api/auth/login
     * Threat context is injected by API Gateway via X-Threat-* headers.
     */
    @PostMapping("/api/auth/login")
    public ResponseEntity<Map<String, Object>> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {

        ThreatContext threat = ThreatContext.from(httpRequest);

        if (threat.isMonitored()) {
            log.warn("MONITORED LOGIN | requestId={} | threatLevel={} | probability={} | username={}",
                    threat.getRequestId(), threat.getThreatLevel(),
                    threat.getThreatProbability(), request.getUsername());
        } else {
            log.info("Login attempt | requestId={} | username={}",
                    threat.getRequestId(), request.getUsername());
        }

        // TODO: Replace with real UserDetailsService + BCrypt password check
        if ("admin".equals(request.getUsername()) && "password".equals(request.getPassword())) {
            return ResponseEntity.ok(Map.of(
                    "status",    "success",
                    "token",     "jwt-token-placeholder",
                    "requestId", threat.getRequestId() != null ? threat.getRequestId() : "",
                    "message",   "Login successful"
            ));
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                "status",  "error",
                "message", "Invalid credentials"
        ));
    }

    /**
     * GET /api/data
     * Protected business endpoint — demonstrates threat-aware response.
     */
    @GetMapping("/api/data")
    public ResponseEntity<Map<String, Object>> getData(HttpServletRequest httpRequest) {
        ThreatContext threat = ThreatContext.from(httpRequest);
        log.debug("Data access | requestId={} | threatLevel={}",
                threat.getRequestId(), threat.getThreatLevel());

        return ResponseEntity.ok(Map.of(
                "data",        "Protected business data",
                "requestId",   threat.getRequestId() != null ? threat.getRequestId() : "",
                "monitored",   threat.isMonitored(),
                "threatLevel", threat.getThreatLevel() != null ? threat.getThreatLevel() : "UNKNOWN"
        ));
    }

    // ─── CAPTCHA Endpoints ────────────────────────────────────────────────

    /**
     * GET /captcha/challenge
     * Renders CAPTCHA challenge page.
     * User arrives here via 307 redirect from API Gateway when action=CAPTCHA.
     */
    @GetMapping("/captcha/challenge")
    public ResponseEntity<Map<String, Object>> captchaChallenge(
            @RequestParam String requestId,
            @RequestParam String redirectTo,
            @RequestParam String threatLevel) {

        log.info("Serving CAPTCHA challenge | requestId={} | threatLevel={}", requestId, threatLevel);

        return ResponseEntity.ok(Map.of(
                "requestId",   requestId,
                "redirectTo",  redirectTo,
                "threatLevel", threatLevel,
                "message",     "Suspicious activity detected. Please verify you are human.",
                "captchaHtml", buildCaptchaHtml(requestId, redirectTo)
        ));
    }

    /**
     * POST /captcha/verify
     * Verifies reCAPTCHA solution, issues a Redis bypass token.
     * Frontend retries original request with X-Captcha-Bypass-Token header.
     */
    @PostMapping("/captcha/verify")
    public ResponseEntity<Map<String, Object>> verifyCaptcha(
            @RequestBody Map<String, String> body) {

        String captchaToken = body.get("captchaToken");
        String requestId    = body.get("requestId");
        String redirectTo   = body.get("redirectTo");

        log.info("CAPTCHA verification | requestId={}", requestId);

        if (captchaService.verify(captchaToken)) {
            String bypassToken = captchaService.issueBypassToken(requestId);
            return ResponseEntity.ok(Map.of(
                    "status",       "success",
                    "bypassToken",  bypassToken,
                    "redirectTo",   redirectTo != null ? redirectTo : "/",
                    "message",      "Verification successful. Retry your request with the bypass token.",
                    "instructions", "Add header: X-Captcha-Bypass-Token: " + bypassToken
            ));
        }

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of(
                "status",  "error",
                "message", "CAPTCHA verification failed. Please try again."
        ));
    }

    // ─── Helper ───────────────────────────────────────────────────────────

    private String buildCaptchaHtml(String requestId, String redirectTo) {
        return """
            <html>
            <head><title>Security Verification</title></head>
            <body>
              <h2>Security Verification Required</h2>
              <p>We detected unusual activity from your IP. Please verify you are human.</p>
              <form id="captcha-form">
                <input type="hidden" id="requestId" value="%s">
                <input type="hidden" id="redirectTo" value="%s">
                <div class="g-recaptcha" data-sitekey="YOUR_SITE_KEY"></div>
                <button type="button" onclick="submitCaptcha()">Continue</button>
              </form>
              <script src="https://www.google.com/recaptcha/api.js"></script>
              <script>
                async function submitCaptcha() {
                  const token = grecaptcha.getResponse();
                  const res = await fetch('/captcha/verify', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                      captchaToken: token,
                      requestId: document.getElementById('requestId').value,
                      redirectTo: document.getElementById('redirectTo').value
                    })
                  });
                  const data = await res.json();
                  if (data.status === 'success') {
                    sessionStorage.setItem('bypassToken', data.bypassToken);
                    window.location.href = data.redirectTo;
                  }
                }
              </script>
            </body>
            </html>
            """.formatted(requestId, redirectTo);
    }
}
package com.threatprotection.auth.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Servlet filter that:
 * 1. Extracts X-Request-ID and X-Threat-Level headers set by the API Gateway
 * 2. Puts them in MDC for structured log correlation across all downstream logs
 * 3. Logs extra detail for MONITOR-level requests
 */
@Slf4j
@Component
public class ThreatHeaderLoggingFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String requestId   = httpRequest.getHeader("X-Request-ID");
        String threatLevel = httpRequest.getHeader("X-Threat-Level");
        String probability = httpRequest.getHeader("X-Threat-Probability");

        try {
            if (requestId != null)   MDC.put("requestId", requestId);
            if (threatLevel != null) MDC.put("threatLevel", threatLevel);

            // Log additional detail for requests under monitoring
            if ("MONITOR".equals(httpRequest.getHeader("X-Threat-Action"))) {
                log.warn("MONITORED REQUEST | requestId={} | threatLevel={} | probability={} | uri={} | ip={}",
                        requestId, threatLevel, probability,
                        httpRequest.getRequestURI(),
                        httpRequest.getRemoteAddr());
            }

            chain.doFilter(request, response);
        } finally {
            MDC.clear(); // Always clear MDC to prevent thread-local leaks in thread pools
        }
    }
}
package com.threatprotection.auth.config;

import com.threatprotection.auth.filter.ThreatHeaderLoggingFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final ThreatHeaderLoggingFilter threatHeaderLoggingFilter;

    public SecurityConfig(ThreatHeaderLoggingFilter threatHeaderLoggingFilter) {
        this.threatHeaderLoggingFilter = threatHeaderLoggingFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(threatHeaderLoggingFilter, UsernamePasswordAuthenticationFilter.class)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/api/**",
                                "/captcha/**",
                                "/actuator/**"
                        ).permitAll()
                        .anyRequest().authenticated()
                );
        return http.build();
    }
}
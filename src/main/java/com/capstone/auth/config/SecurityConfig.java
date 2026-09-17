package com.capstone.auth.config;

import com.capstone.auth.security.JwtAuthenticationFilter;
import com.capstone.auth.security.RateLimiterFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final RateLimiterFilter rateLimiterFilter;


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                // Disable CSRF because this is a stateless REST API
                .csrf(csrf -> csrf.disable())

                // JWT authentication does not use HTTP sessions
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                // Endpoint authorization
                .authorizeHttpRequests(auth -> auth
                        // Login does not require a JWT
                        .requestMatchers("/login").permitAll()

                        // These endpoints require a valid JWT
                        .requestMatchers("/auth", "/logout").authenticated()

                        // Other endpoints are currently allowed
                        .anyRequest().permitAll()
                )

                // Disable Spring Security's default /logout handling.
                // Our AuthController handles POST /logout instead.
                .logout(logout -> logout.disable())

                .addFilterBefore(rateLimiterFilter, UsernamePasswordAuthenticationFilter.class)

                // Run our JWT filter before Spring's username/password filter
                .addFilterBefore(
                        jwtAuthenticationFilter,
                        UsernamePasswordAuthenticationFilter.class
                );

        return http.build();
    }
}
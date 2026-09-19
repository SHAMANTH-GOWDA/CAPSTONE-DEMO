package com.capstone.auth.security;

import com.capstone.auth.service.JwtService;
import com.capstone.auth.service.TokenStoreService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final TokenStoreService tokenStoreService;

    public JwtAuthenticationFilter(
            JwtService jwtService,
            TokenStoreService tokenStoreService
    ) {
        this.jwtService = jwtService;
        this.tokenStoreService = tokenStoreService;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        // Get Authorization header
        String authorizationHeader =
                request.getHeader("Authorization");

        // If there is no Bearer token, continue the filter chain
        if (authorizationHeader == null
                || !authorizationHeader.startsWith("Bearer ")) {

            filterChain.doFilter(request, response);
            return;
        }

        // Extract token
        String token =
                authorizationHeader.substring(7);

        try {

            // =====================================================
            // 1. CHECK JWT VALIDITY
            // =====================================================

            if (!jwtService.isTokenValid(token)) {

                sendUnauthorized(
                        response,
                        "Invalid or expired JWT token"
                );

                return;
            }


            // =====================================================
            // 2. MAKE SURE IT IS AN ACCESS TOKEN
            // =====================================================

            if (!jwtService.isAccessToken(token)) {

                sendUnauthorized(
                        response,
                        "Refresh token cannot be used as an access token"
                );

                return;
            }


            // =====================================================
            // 3. CHECK WHETHER ACCESS TOKEN IS ACTIVE
            // =====================================================

            if (!tokenStoreService.isTokenActive(token)) {

                sendUnauthorized(
                        response,
                        "Token has been revoked"
                );

                return;
            }


            // =====================================================
            // 4. EXTRACT USERNAME AND ROLE
            // =====================================================

            String username =
                    jwtService.extractUsername(token);

            String role =
                    jwtService.extractRole(token);


            // =====================================================
            // 5. CHECK ROLE
            // =====================================================

            if (role == null || role.isBlank()) {

                sendUnauthorized(
                        response,
                        "JWT does not contain a valid role"
                );

                return;
            }


            // =====================================================
            // 6. CREATE SPRING SECURITY AUTHENTICATION
            // =====================================================

            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(
                            username,
                            null,
                            List.of(
                                    new SimpleGrantedAuthority(
                                            "ROLE_" + role
                                    )
                            )
                    );


            // =====================================================
            // 7. STORE AUTHENTICATION IN SECURITY CONTEXT
            // =====================================================

            SecurityContextHolder
                    .getContext()
                    .setAuthentication(authentication);


            // =====================================================
            // 8. CONTINUE REQUEST
            // =====================================================

            filterChain.doFilter(request, response);

        }

        // =========================================================
        // JWT EXPIRED
        // =========================================================

        catch (io.jsonwebtoken.ExpiredJwtException exception) {

            SecurityContextHolder.clearContext();

            sendUnauthorized(
                    response,
                    "JWT token has expired"
            );
        }

        // =========================================================
        // ANY OTHER JWT ERROR
        // =========================================================

        catch (Exception exception) {

            SecurityContextHolder.clearContext();

            sendUnauthorized(
                    response,
                    "Invalid JWT token"
            );
        }
    }


    // =============================================================
    // SEND 401 RESPONSE
    // =============================================================

    private void sendUnauthorized(
            HttpServletResponse response,
            String message
    ) throws IOException {

        response.setStatus(
                HttpServletResponse.SC_UNAUTHORIZED
        );

        response.setContentType("application/json");

        response.getWriter().write(
                "{\"status\":401,"
                        + "\"error\":\"UNAUTHORIZED\","
                        + "\"message\":\""
                        + message
                        + "\"}"
        );
    }
}
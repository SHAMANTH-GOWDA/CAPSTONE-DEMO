package com.capstone.auth.security;

import com.capstone.auth.service.JwtService;
import com.capstone.auth.service.TokenStoreService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Component
@AllArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final TokenStoreService tokenStoreService;


    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {


        String authorizationHeader =
                request.getHeader("Authorization");


        if (authorizationHeader == null
                || !authorizationHeader.startsWith("Bearer ")) {

            filterChain.doFilter(request, response);
            return;
        }


        String token =
                authorizationHeader.substring(7);
        try {

            if (!jwtService.isTokenValid(token)) {
                sendUnauthorized(
                        response,
                        "Invalid or expired JWT token"
                );
                return;
            }

            if (!jwtService.isAccessToken(token)) {

                sendUnauthorized(
                        response,
                        "Refresh token cannot be used as an access token"
                );

                return;
            }


            if (!tokenStoreService.isTokenActive(token)) {

                sendUnauthorized(
                        response,
                        "Token has been revoked"
                );

                return;
            }

            String username = jwtService.extractUsername(token);

            String role = jwtService.extractRole(token);

            if (role == null || role.isBlank()) {

                sendUnauthorized(
                        response,
                        "JWT does not contain a valid role"
                );

                return;
            }

            role = role.toUpperCase();

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

            SecurityContextHolder
                    .getContext()
                    .setAuthentication(authentication);

            filterChain.doFilter(request, response);

        }

        catch (io.jsonwebtoken.ExpiredJwtException exception) {

            SecurityContextHolder.clearContext();

            sendUnauthorized(
                    response,
                    "JWT token has expired"
            );
        }

        catch (Exception exception) {

            SecurityContextHolder.clearContext();

            sendUnauthorized(
                    response,
                    "Invalid JWT token"
            );
        }
    }


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
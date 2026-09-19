package com.capstone.auth.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;

@Service
public class JwtService {

    private static final String SECRET_KEY =
            "capstone-auth-secret-key-for-jwt-security-2025";

    // Access token = 15 minutes
    private static final long ACCESS_TOKEN_EXPIRATION =
            15 * 60 * 1000L;

    // Refresh token = 7 days
    private static final long REFRESH_TOKEN_EXPIRATION =
            7 * 24 * 60 * 60 * 1000L;

    private final SecretKey key = Keys.hmacShaKeyFor(
            SECRET_KEY.getBytes(StandardCharsets.UTF_8)
    );

    // ==========================================
    // ACCESS TOKEN
    // ==========================================


    public String generateToken(String username, String role) {

        Instant now = Instant.now();

        Instant expiration =
                now.plusMillis(ACCESS_TOKEN_EXPIRATION);

        return Jwts.builder()
                .subject(username)
                .claim("role", role)
                .claim("tokenType", "access")
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiration))
                .signWith(key)
                .compact();
    }

    // ==========================================
    // REFRESH TOKEN
    // ==========================================

    public String generateRefreshToken(String username) {

        Instant now = Instant.now();

        Instant expiration =
                now.plusMillis(REFRESH_TOKEN_EXPIRATION);

        return Jwts.builder()
                .subject(username)
                .claim("tokenType", "refresh")
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiration))
                .signWith(key)
                .compact();
    }

    // ==========================================
    // EXTRACT USERNAME
    // ==========================================

    public String extractUsername(String token) {

        return extractClaims(token)
                .getSubject();
    }

    // ==========================================
    // EXTRACT ROLE
    // ==========================================

    public String extractRole(String token) {

        return extractClaims(token)
                .get("role", String.class);
    }

    // ==========================================
    // EXTRACT EXPIRATION
    // ==========================================

    public Instant extractExpiration(String token) {

        return extractClaims(token)
                .getExpiration()
                .toInstant();
    }

    // ==========================================
    // CHECK TOKEN TYPE
    // ==========================================

    public boolean isRefreshToken(String token) {

        String tokenType = extractClaims(token)
                .get("tokenType", String.class);

        return "refresh".equals(tokenType);
    }

    public boolean isAccessToken(String token) {

        String tokenType = extractClaims(token)
                .get("tokenType", String.class);

        return "access".equals(tokenType);
    }

    // ==========================================
    // VALIDATE TOKEN
    // ==========================================

    public boolean isTokenValid(String token) {

        try {

            Claims claims = extractClaims(token);

            return claims.getSubject() != null
                    && claims.getExpiration() != null
                    && claims.getExpiration()
                    .toInstant()
                    .isAfter(Instant.now());

        } catch (Exception exception) {

            return false;
        }
    }

    // ==========================================
    // EXTRACT CLAIMS
    // ==========================================

    private Claims extractClaims(String token) {

        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
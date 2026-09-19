package com.capstone.auth.service;

import com.capstone.auth.model.RefreshToken;
import com.capstone.auth.repository.RefreshTokenRepository;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Service
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtService jwtService;

    public RefreshTokenService(
            RefreshTokenRepository refreshTokenRepository,
            JwtService jwtService
    ) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.jwtService = jwtService;
    }

    public RefreshToken createRefreshToken(String username) {

        String token = jwtService.generateRefreshToken(username);

        Instant expiresAt = jwtService.extractExpiration(token);

        RefreshToken refreshToken = new RefreshToken(
                token,
                username,
                expiresAt
        );

        return refreshTokenRepository.save(refreshToken);
    }

    public RefreshToken validateRefreshToken(String token) {

        RefreshToken refreshToken = refreshTokenRepository
                .findByToken(token)
                .orElseThrow(() ->
                        new IllegalArgumentException(
                                "Refresh token not found"
                        )
                );

        if (refreshToken.isRevoked()) {
            throw new IllegalArgumentException(
                    "Refresh token has been revoked"
            );
        }

        if (refreshToken.getExpiresAt().isBefore(Instant.now())) {
            throw new IllegalArgumentException(
                    "Refresh token has expired"
            );
        }

        if (!jwtService.isTokenValid(token)) {
            throw new IllegalArgumentException(
                    "Invalid refresh token"
            );
        }

        if (!jwtService.isRefreshToken(token)) {
            throw new IllegalArgumentException(
                    "Token is not a refresh token"
            );
        }

        return refreshToken;
    }

    public void revokeRefreshToken(String token) {

        RefreshToken refreshToken = refreshTokenRepository
                .findByToken(token)
                .orElseThrow(() ->
                        new IllegalArgumentException(
                                "Refresh token not found"
                        )
                );

        refreshToken.setRevoked(true);

        refreshTokenRepository.save(refreshToken);
    }
}
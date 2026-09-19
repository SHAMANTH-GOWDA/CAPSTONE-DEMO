package com.capstone.auth.dto.response;

import java.time.Instant;

public class LoginResponse {

    private String accessToken;
    private String refreshToken;
    private String username;
    private Instant expiresAt;

    public LoginResponse(
            String accessToken,
            String refreshToken,
            String username,
            Instant expiresAt
    ) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.username = username;
        this.expiresAt = expiresAt;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public String getUsername() {
        return username;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }
}
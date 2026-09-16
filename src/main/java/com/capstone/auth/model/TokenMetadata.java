package com.capstone.auth.model;

import java.time.Instant;

public class TokenMetadata {

    private String token;
    private String username;
    private Instant issuedAt;
    private Instant expiresAt;

    public TokenMetadata() {
    }

    public TokenMetadata(String token, String username, Instant issuedAt, Instant expiresAt) {
        this.token = token;
        this.username = username;
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public Instant getIssuedAt() {
        return issuedAt;
    }

    public void setIssuedAt(Instant issuedAt) {
        this.issuedAt = issuedAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(Instant expiresAt) {
        this.expiresAt = expiresAt;
    }
}
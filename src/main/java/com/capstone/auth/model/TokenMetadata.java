package com.capstone.auth.model;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;

import java.time.Instant;

@Setter
@Getter
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

}
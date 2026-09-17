package com.capstone.auth.service;

import com.capstone.auth.dto.request.LoginRequest;
import com.capstone.auth.dto.response.AuthValidationResponse;
import com.capstone.auth.dto.response.LoginResponse;
import com.capstone.auth.exception.InvalidCredentialsException;
import com.capstone.auth.exception.InvalidTokenException;
import com.capstone.auth.exception.TokenExpiredException;
import com.capstone.auth.model.TokenMetadata;
import com.capstone.auth.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private static final User DEFAULT_USER =
            new User("admin", "password123");

    private final JwtService jwtService;
    private final TokenStoreService tokenStoreService;


    @Override
    public LoginResponse authenticate(LoginRequest loginRequest) throws InterruptedException {

        if (!DEFAULT_USER.getUsername().equals(loginRequest.getUsername())
                || !DEFAULT_USER.getPassword().equals(loginRequest.getPassword())) {

            throw new InvalidCredentialsException("Invalid username or password");
        }

        String token = jwtService.generateToken(loginRequest.getUsername());

        Instant issuedAt = Instant.now();
        Instant expiresAt = jwtService.extractExpiration(token);

        TokenMetadata tokenMetadata = new TokenMetadata(
                token,
                loginRequest.getUsername(),
                issuedAt,
                expiresAt
        );

        tokenStoreService.storeToken(tokenMetadata);


        return new LoginResponse(
                token,
                loginRequest.getUsername(),
                expiresAt
        );
    }

    @Override
    public AuthValidationResponse validate(String token) {

        if (!jwtService.isTokenValid(token)) {
            throw new InvalidTokenException("Invalid JWT token");
        }

        Instant expiresAt = jwtService.extractExpiration(token);

        if (expiresAt.isBefore(Instant.now())) {
            throw new TokenExpiredException("JWT token has expired");
        }

        if (!tokenStoreService.isTokenActive(token)) {
            throw new InvalidTokenException("Token has been revoked");
        }

        String username = jwtService.extractUsername(token);

        return new AuthValidationResponse(true, username);
    }

    @Override
    public void invalidate(String token) {

        tokenStoreService.revokeToken(token);
    }
}
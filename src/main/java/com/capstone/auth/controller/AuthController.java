package com.capstone.auth.controller;

import com.capstone.auth.dto.request.LoginRequest;
import com.capstone.auth.dto.response.AuthValidationResponse;
import com.capstone.auth.dto.response.LoginResponse;
import com.capstone.auth.service.AuthService;
import com.capstone.auth.service.TokenStoreService;
import io.github.resilience4j.ratelimiter.RequestNotPermitted;
import io.github.resilience4j.ratelimiter.annotation.RateLimiter;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
@Tag(name = "Authentication API")
public class AuthController {

    private final AuthService authService;
    private final TokenStoreService tokenStoreService;
    private static final String RateLimiter = "LoginRateLimiter";

    // Login
    @PostMapping("/login")
    @RateLimiter(name = RateLimiter , fallbackMethod = "LoginFallBack")
    public ResponseEntity<LoginResponse> login(
            @Valid @RequestBody LoginRequest loginRequest) {

        LoginResponse response = authService.authenticate(loginRequest);

        return ResponseEntity.ok(response);
    }

    // Validate JWT authentication
    @GetMapping("auth")
    public ResponseEntity<AuthValidationResponse> validate(
            @RequestHeader("Authorization") String authorizationHeader) {

        String token = extractToken(authorizationHeader);

        AuthValidationResponse response = authService.validate(token);

        return ResponseEntity.ok(response);
    }

    // Logout
    @PostMapping("/logout")
    public ResponseEntity<String> logout(
            @RequestHeader("Authorization") String authorizationHeader) {

        String token = extractToken(authorizationHeader);

        if(!tokenStoreService.isTokenActive(token)) {
            return new ResponseEntity<>("Token has been revoked", HttpStatus.UNAUTHORIZED);
        }
        authService.invalidate(token);
        return new ResponseEntity<>("Logout" , HttpStatus.OK);
    }

    // Extract JWT from Authorization header
    private String extractToken(String authorizationHeader) {

        if (authorizationHeader == null ||
                !authorizationHeader.startsWith("Bearer ")) {

            throw new IllegalArgumentException(
                    "Authorization header must use Bearer token"
            );
        }

        return authorizationHeader.substring(7);
    }

    public ResponseEntity<?> LoginFallBack(LoginRequest loginRequest , RequestNotPermitted requestNotPermitted) {
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(
                Map.of("message", "Too many requests for this resource","status", HttpStatus.TOO_MANY_REQUESTS.value())
        );
    }
}
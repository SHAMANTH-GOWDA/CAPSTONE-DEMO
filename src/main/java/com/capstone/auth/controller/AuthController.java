package com.capstone.auth.controller;

import com.capstone.auth.dto.request.LoginRequest;
import com.capstone.auth.dto.response.AuthValidationResponse;
import com.capstone.auth.dto.response.LoginResponse;
import com.capstone.auth.service.AuthService;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
@Tag(name = "Authentication API")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    // Login
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(
            @Valid @RequestBody LoginRequest loginRequest) throws InterruptedException {

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
    public ResponseEntity<Void> logout(
            @RequestHeader("Authorization") String authorizationHeader) {

        String token = extractToken(authorizationHeader);

        authService.invalidate(token);

        return ResponseEntity.ok().build();
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
}
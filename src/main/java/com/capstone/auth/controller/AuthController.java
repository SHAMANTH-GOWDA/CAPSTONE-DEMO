package com.capstone.auth.controller;

import com.capstone.auth.dto.request.LoginRequest;
import com.capstone.auth.dto.request.RefreshTokenRequest;
import com.capstone.auth.dto.request.SignupRequest;
import com.capstone.auth.dto.response.AuthValidationResponse;
import com.capstone.auth.dto.response.LoginResponse;
import com.capstone.auth.dto.response.UserResponse;
import com.capstone.auth.service.AuthService;
import io.github.resilience4j.ratelimiter.RequestNotPermitted;
import io.github.resilience4j.ratelimiter.annotation.RateLimiter;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
@Tag(name = "Authentication API")
public class AuthController {

    private final AuthService authService;
    private static final String RateLimiter = "LoginRateLimiter";

    // Login
    @PostMapping("/login")
    @RateLimiter(name = RateLimiter , fallbackMethod = "LoginFallBack")
    public ResponseEntity<LoginResponse> login(
            @Valid @RequestBody LoginRequest loginRequest) throws InterruptedException {

        LoginResponse response = authService.authenticate(loginRequest);

        return ResponseEntity.ok(response);
    }

    @PostMapping("/signup")
    public ResponseEntity<String> signup(
            @RequestBody SignupRequest signupRequest
    ) {
        authService.signup(signupRequest);

        return ResponseEntity.ok(
                "User registered successfully"
        );
    }


    @PostMapping("/refresh")
    public LoginResponse refresh(
            @RequestBody RefreshTokenRequest request
    ) {
        return authService.refreshAccessToken(
                request.getRefreshToken()
        );
    }

    // Validate JWT authentication
    @GetMapping("/auth")
    public ResponseEntity<AuthValidationResponse> validate(
            HttpServletRequest request) {

        String authorization = request.getHeader("Authorization");

        if (authorization == null
                || !authorization.startsWith("Bearer ")) {
            return ResponseEntity.badRequest().build();
        }

        String token = authorization.substring(7);

        return ResponseEntity.ok(
                authService.validate(token)
        );
    }

    // Logout
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            HttpServletRequest request) {

        String authorization = request.getHeader("Authorization");

        if (authorization != null
                && authorization.startsWith("Bearer ")) {

            String token = authorization.substring(7);
            authService.invalidate(token);
        }

        return ResponseEntity.noContent().build();
    }

    @GetMapping("/admin/test")
    public ResponseEntity<String> adminTest() {
        return ResponseEntity.ok(
                "Admin access successful"
        );
    }

    @GetMapping("/user/test")
    public ResponseEntity<String> userTest() {
        return ResponseEntity.ok(
                "User access successful"
        );
    }


    public ResponseEntity<?> LoginFallBack(LoginRequest loginRequest , RequestNotPermitted requestNotPermitted) {
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).body(
                Map.of("message", "Too many requests for this resource","status", HttpStatus.TOO_MANY_REQUESTS.value())
        );
    }
}
package com.capstone.auth.controller;

import com.capstone.auth.dto.request.LoginRequest;
import com.capstone.auth.dto.response.AuthValidationResponse;
import com.capstone.auth.dto.response.LoginResponse;
import com.capstone.auth.exception.InvalidTokenException;
import com.capstone.auth.service.AuthService;
import io.github.resilience4j.ratelimiter.RequestNotPermitted;
import io.github.resilience4j.ratelimiter.annotation.RateLimiter;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MissingRequestHeaderException;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
@Tag(name = "Authentication API")
public class AuthController {

    private final AuthService authService;
    private static final String RateLimiter = "LoginRateLimiter";


    @PostMapping("/login")
    @RateLimiter(name = RateLimiter)
    public ResponseEntity<LoginResponse> login(
            @Valid @RequestBody LoginRequest loginRequest) {

        return ResponseEntity.ok(
                authService.authenticate(loginRequest)
        );
    }

    @GetMapping("/auth")
    public ResponseEntity<AuthValidationResponse> validate(
            HttpServletRequest request) {

        String authorization = request.getHeader("Authorization");

        if (authorization == null
                || !authorization.startsWith("Bearer ")) {

            throw new InvalidTokenException("Missing or malformed Authorization header");
        }

        String token = authorization.substring(7);

        return ResponseEntity.ok(
                authService.validate(token)
        );
    }

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


}
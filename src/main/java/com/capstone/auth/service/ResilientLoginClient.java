package com.capstone.auth.service;

import com.capstone.auth.dto.request.LoginRequest;
import com.capstone.auth.dto.response.AuthValidationResponse;
import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import io.github.resilience4j.ratelimiter.annotation.RateLimiter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

@Service
@RequiredArgsConstructor
public class ResilientLoginClient {
    private final MockExternalService mockExternalService;

    private static final String MockExternalService = "mockExternalService";

    @CircuitBreaker(name = MockExternalService , fallbackMethod = "getMockLogin")
    public ResponseEntity<String> login(LoginRequest loginRequest) throws InterruptedException {
        return mockExternalService.login(loginRequest);
    }

    public ResponseEntity<String> getMockLogin(LoginRequest loginRequest , Throwable throwable) {
        return new ResponseEntity<>("Service error and Failure", HttpStatus.UNAUTHORIZED);
    }

}
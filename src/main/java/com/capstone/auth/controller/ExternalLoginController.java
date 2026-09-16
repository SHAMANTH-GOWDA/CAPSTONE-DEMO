package com.capstone.auth.controller;


import com.capstone.auth.dto.request.LoginRequest;
import com.capstone.auth.service.ResilientLoginClient;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/mock-login")
@RequiredArgsConstructor
@Tag(name = "External API for Authentication")
public class ExternalLoginController {

    private final ResilientLoginClient resilientLoginClient;

    @PostMapping
    public ResponseEntity<String> login(@Valid @RequestBody LoginRequest loginRequest) {
        return resilientLoginClient.login(loginRequest);
    }

}
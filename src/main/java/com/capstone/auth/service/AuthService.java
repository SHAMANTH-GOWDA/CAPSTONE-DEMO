package com.capstone.auth.service;

import com.capstone.auth.dto.request.LoginRequest;
import com.capstone.auth.dto.request.SignupRequest;
import com.capstone.auth.dto.response.AuthValidationResponse;
import com.capstone.auth.dto.response.LoginResponse;

import com.capstone.auth.dto.request.SignupRequest;

public interface AuthService {

    LoginResponse authenticate(LoginRequest loginRequest) throws InterruptedException;

    AuthValidationResponse validate(String token);

    void invalidate(String token);

    LoginResponse refreshAccessToken(String refreshToken);

    void signup(SignupRequest signupRequest);
}
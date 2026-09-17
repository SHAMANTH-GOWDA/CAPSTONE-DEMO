package com.capstone.auth.service;

import com.capstone.auth.dto.request.LoginRequest;
import com.capstone.auth.dto.response.AuthValidationResponse;
import com.capstone.auth.dto.response.LoginResponse;

public interface AuthService {

    LoginResponse authenticate(LoginRequest loginRequest) throws InterruptedException;

    AuthValidationResponse validate(String token);

    void invalidate(String token);
}
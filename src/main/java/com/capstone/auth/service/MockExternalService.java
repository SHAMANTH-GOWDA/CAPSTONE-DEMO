package com.capstone.auth.service;

import com.capstone.auth.dto.request.LoginRequest;
import com.capstone.auth.dto.response.LoginResponse;
import com.capstone.auth.exception.ExternalServiceException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

import java.util.Random;

@Service
public class MockExternalService {

    public ResponseEntity<String> login(LoginRequest loginRequest) {
        if(Math.random() > 0.5){
            throw new ExternalServiceException("External Service Error");
        }
        return new ResponseEntity<>("Login Successful", HttpStatus.OK);
    }
}
package com.capstone.auth.service;

import com.capstone.auth.dto.request.LoginRequest;
import com.capstone.auth.dto.response.LoginResponse;
import com.capstone.auth.exception.ExternalServiceException;
import com.capstone.auth.exception.InvalidCredentialsException;
import com.capstone.auth.model.User;
import io.github.resilience4j.timelimiter.annotation.TimeLimiter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.util.Random;

@Service
@RequiredArgsConstructor
public class MockExternalService {

    public ResponseEntity<String> login(LoginRequest loginRequest) throws InterruptedException {

        if(Math.random() > 0.5){
            throw new ExternalServiceException("External Service Error");
        }
//        Thread.sleep(2000);
        return new ResponseEntity<>("Login Successful", HttpStatus.OK);
    }
}
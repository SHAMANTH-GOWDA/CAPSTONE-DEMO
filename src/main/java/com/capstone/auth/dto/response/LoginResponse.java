package com.capstone.auth.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;

import java.time.Instant;

@Setter
@Getter
@RequiredArgsConstructor
@AllArgsConstructor
public class LoginResponse {

    private String token;
    private String username;
    //private Instant expiresAt;


}
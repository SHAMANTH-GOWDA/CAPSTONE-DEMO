package com.capstone.auth.dto.response;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class AuthValidationResponse {

    private boolean authenticated;
    private String username;

    public AuthValidationResponse() {
    }

    public AuthValidationResponse(boolean authenticated, String username) {
        this.authenticated = authenticated;
        this.username = username;
    }

}
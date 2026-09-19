package com.capstone.auth.dto.response;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class ApiErrorResponse {

    private int status;
    private String error;
    private String message;

    public ApiErrorResponse() {
    }

    public ApiErrorResponse(String message) {
        this.message = message;
    }

    public ApiErrorResponse(int status, String error, String message) {
        this.status = status;
        this.error = error;
        this.message = message;
    }

}
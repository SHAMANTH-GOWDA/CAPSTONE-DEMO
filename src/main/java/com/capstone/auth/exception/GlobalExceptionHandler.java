package com.capstone.auth.exception;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import com.capstone.auth.dto.response.ApiErrorResponse;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger logger =
            LoggerFactory.getLogger(GlobalExceptionHandler.class);


    // 503 - External Service Error
    @ExceptionHandler(ExternalServiceException.class)
    public ResponseEntity<ApiErrorResponse> handleExternalServiceException(
            ExternalServiceException exception,
            HttpServletRequest request) {logger.error(
                "EXCEPTION | type=ExternalServiceException | method={} | uri={} | message={}",
                request.getMethod(),
                request.getRequestURI(),
                exception.getMessage(),
                exception
        );

        ApiErrorResponse error =
                new ApiErrorResponse(exception.getMessage());

        return ResponseEntity
                .status(HttpStatus.SERVICE_UNAVAILABLE)
                .body(error);
    }


    // 401 - Invalid Credentials
    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<ApiErrorResponse> handleInvalidCredentialsException(
            InvalidCredentialsException exception,
            HttpServletRequest request) {

        logger.warn(
                "EXCEPTION | type=InvalidCredentialsException | method={} | uri={} | message={}",
                request.getMethod(),
                request.getRequestURI(),
                exception.getMessage()
        );

        ApiErrorResponse error =
                new ApiErrorResponse(exception.getMessage());

        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(error);
    }


    // 401 - Invalid Token
    @ExceptionHandler(InvalidTokenException.class)
    public ResponseEntity<ApiErrorResponse> handleInvalidTokenException(
            InvalidTokenException exception,
            HttpServletRequest request) {

        logger.warn(
                "EXCEPTION | type=InvalidTokenException | method={} | uri={} | message={}",
                request.getMethod(),
                request.getRequestURI(),
                exception.getMessage()
        );

        ApiErrorResponse error =
                new ApiErrorResponse(exception.getMessage());

        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(error);
        
    }
    
    // 401 - Token Expired
    @ExceptionHandler(TokenExpiredException.class)
    public ResponseEntity<ApiErrorResponse> handleTokenExpiredException(
            TokenExpiredException exception,
            HttpServletRequest request) {

        logger.warn(
                "EXCEPTION | type=TokenExpiredException | method={} | uri={} | message={}",
                request.getMethod(),
                request.getRequestURI(),
                exception.getMessage()
        );

        ApiErrorResponse error =
                new ApiErrorResponse(exception.getMessage());

        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(error);
    }


    // 500 - Unexpected Error
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiErrorResponse> handleGenericException(
            Exception exception,
            HttpServletRequest request) {

        logger.error(
                "EXCEPTION | type={} | method={} | uri={} | message={}",
                exception.getClass().getSimpleName(),
                request.getMethod(),
                request.getRequestURI(),
                exception.getMessage(),
                exception
        );

        ApiErrorResponse error =
                new ApiErrorResponse("An unexpected error occurred");

        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(error);
    }
}

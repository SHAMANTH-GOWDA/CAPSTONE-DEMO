package com.capstone.auth.service;

import com.capstone.auth.dto.request.LoginRequest;
import com.capstone.auth.dto.response.AuthValidationResponse;
import com.capstone.auth.dto.response.LoginResponse;
import com.capstone.auth.exception.*;
import com.capstone.auth.model.TokenMetadata;
import com.capstone.auth.model.User;
import com.capstone.auth.repository.UserRepository;
import io.github.resilience4j.circuitbreaker.CallNotPermittedException;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import jakarta.persistence.PersistenceException;
import org.springframework.dao.DataAccessException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;

@Service
public class AuthServiceImpl implements AuthService {

    private static final int MAX_FAILED_ATTEMPTS = 5;

    private static final String DB_SERVICE = "dbService";

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final TokenStoreService tokenStoreService;
    private final PasswordEncoder passwordEncoder;
    private final CircuitBreakerRegistry circuitBreakerRegistry;

    public AuthServiceImpl(
            UserRepository userRepository,
            JwtService jwtService,
            TokenStoreService tokenStoreService,
            PasswordEncoder passwordEncoder,
            CircuitBreakerRegistry circuitBreakerRegistry) {

        this.userRepository = userRepository;
        this.jwtService = jwtService;
        this.tokenStoreService = tokenStoreService;
        this.passwordEncoder = passwordEncoder;
        this.circuitBreakerRegistry = circuitBreakerRegistry;
    }


    @Override
    public LoginResponse authenticate(LoginRequest loginRequest) {

        String username = loginRequest.getUsername()
                .trim()
                .toLowerCase();
        User user = findUserByUsername(username)
                .orElseThrow(() ->
                        new InvalidCredentialsException(
                                "Invalid username or password"
                        )
                );

        if (user.isLocked()) {

            throw new AccountLockedException(
                    "Account is locked due to too many failed login attempts"
            );
        }


        if (!passwordEncoder.matches(
                loginRequest.getPassword(),
                user.getPassword())) {

            int failedAttempts =
                    user.getFailedLoginAttempts() + 1;

            user.setFailedLoginAttempts(failedAttempts);

            if (failedAttempts >= MAX_FAILED_ATTEMPTS) {
                user.setLocked(true);
            }

            saveUser(user);

            throw new InvalidCredentialsException(
                    "Invalid username or password"
            );
        }

        user.setFailedLoginAttempts(0);

        saveUser(user);

        String token = jwtService.generateToken(
                user.getUsername(),
                user.getRole()
        );

        Instant issuedAt = Instant.now();

        Instant expiresAt =
                jwtService.extractExpiration(token);


        TokenMetadata tokenMetadata =
                new TokenMetadata(
                        token,
                        user.getUsername(),
                        issuedAt,
                        expiresAt
                );
        tokenStoreService.storeToken(tokenMetadata);
        return new LoginResponse(
                token,
                user.getUsername()
        );
    }


    private Optional<User> findUserByUsername(String username) {

        CircuitBreaker circuitBreaker =
                circuitBreakerRegistry.circuitBreaker(DB_SERVICE);

        try {

            return circuitBreaker.executeSupplier(
                    () -> userRepository.findByUsername(username)
            );

        } catch (CallNotPermittedException ex) {
            throw new ExternalServiceException(
                    "Authentication service is currently unavailable due to database connection issues. Please try again later."
            );
        } catch (DataAccessException | PersistenceException ex) {

            throw new ExternalServiceException(
                    "Authentication service is currently unavailable due to database connection issues. Please try again later."
            );
        }
    }


    private User saveUser(User user) {

        CircuitBreaker circuitBreaker =
                circuitBreakerRegistry.circuitBreaker(DB_SERVICE);

        try {

            return circuitBreaker.executeSupplier(
                    () -> userRepository.save(user)
            );

        } catch (CallNotPermittedException ex) {

            throw new ExternalServiceException(
                    "Authentication service is currently unavailable due to database connection issues. Please try again later."
            );

        } catch (DataAccessException | PersistenceException ex) {

            throw new ExternalServiceException(
                    "Authentication service is currently unavailable due to database connection issues. Please try again later."
            );
        }
    }
    @Override
    public AuthValidationResponse validate(String token) {

        if (!jwtService.isTokenValid(token)) {

            throw new InvalidTokenException(
                    "Invalid JWT token"
            );
        }

        Instant expiresAt =
                jwtService.extractExpiration(token);

        if (expiresAt.isBefore(Instant.now())) {

            throw new TokenExpiredException(
                    "JWT token has expired"
            );
        }

        if (!tokenStoreService.isTokenActive(token)) {

            throw new InvalidTokenException(
                    "Token has been revoked"
            );
        }

        String username =
                jwtService.extractUsername(token);

        return new AuthValidationResponse(
                true,
                username
        );
    }

    @Override
    public void invalidate(String token) {
        tokenStoreService.revokeToken(token);
    }
}
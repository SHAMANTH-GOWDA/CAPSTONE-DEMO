package com.capstone.auth.service;

import com.capstone.auth.dto.request.LoginRequest;
import com.capstone.auth.dto.response.AuthValidationResponse;
import com.capstone.auth.dto.response.LoginResponse;
import com.capstone.auth.dto.request.SignupRequest;
import com.capstone.auth.exception.AccountLockedException;
import com.capstone.auth.exception.InvalidCredentialsException;
import com.capstone.auth.exception.InvalidTokenException;
import com.capstone.auth.exception.TokenExpiredException;
import com.capstone.auth.model.RefreshToken;
import com.capstone.auth.model.TokenMetadata;
import com.capstone.auth.model.User;
import com.capstone.auth.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Service
public class AuthServiceImpl implements AuthService {

    private static final int MAX_FAILED_ATTEMPTS = 5;

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final TokenStoreService tokenStoreService;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenService refreshTokenService;

    public AuthServiceImpl(
            UserRepository userRepository,
            JwtService jwtService,
            TokenStoreService tokenStoreService,
            PasswordEncoder passwordEncoder,
            RefreshTokenService refreshTokenService
    ) {
        this.userRepository = userRepository;
        this.jwtService = jwtService;
        this.tokenStoreService = tokenStoreService;
        this.passwordEncoder = passwordEncoder;
        this.refreshTokenService = refreshTokenService;
    }

    @Override
    public LoginResponse authenticate(LoginRequest loginRequest) {

        String username = loginRequest.getUsername()
                .trim()
                .toLowerCase();

        User user = userRepository
                .findByUsername(username)
                .orElseThrow(() ->
                        new InvalidCredentialsException(
                                "Invalid username or password"
                        )
                );

        // Check whether the account is locked
        if (user.isLocked()) {
            throw new AccountLockedException(
                    "Account is locked due to too many failed login attempts"
            );
        }

        // Check password
        if (!passwordEncoder.matches(
                loginRequest.getPassword(),
                user.getPassword()
        )) {

            int failedAttempts =
                    user.getFailedLoginAttempts() + 1;

            user.setFailedLoginAttempts(failedAttempts);

            if (failedAttempts >= MAX_FAILED_ATTEMPTS) {
                user.setLocked(true);
            }

            userRepository.save(user);

            throw new InvalidCredentialsException(
                    "Invalid username or password"
            );
        }

        // Successful login
        user.setFailedLoginAttempts(0);
        userRepository.save(user);

        // ==============================
        // GENERATE ACCESS TOKEN
        // ==============================

        String accessToken = jwtService.generateToken(
                user.getUsername(),
                user.getRole()
        );

        // When the access token was issued
        Instant issuedAt = Instant.now();

        // When the access token will expire
        Instant expiresAt =
                jwtService.extractExpiration(accessToken);

        // ==============================
        // STORE ACCESS TOKEN
        // ==============================

        TokenMetadata tokenMetadata = new TokenMetadata(
                accessToken,
                user.getUsername(),
                issuedAt,
                expiresAt
        );

        tokenStoreService.storeToken(tokenMetadata);

        // ==============================
        // GENERATE REFRESH TOKEN
        // ==============================

        RefreshToken refreshToken =
                refreshTokenService.createRefreshToken(
                        user.getUsername()
                );

        // ==============================
        // RETURN BOTH TOKENS
        // ==============================

        return new LoginResponse(
                accessToken,
                refreshToken.getToken(),
                user.getUsername(),
                expiresAt
        );
    }

    @Override
    public void signup(SignupRequest signupRequest) {

        String username = signupRequest.getUsername()
                .trim()
                .toLowerCase();

        if (userRepository.findByUsername(username).isPresent()) {
            throw new IllegalArgumentException(
                    "Username already exists"
            );
        }

        User user = new User();

        user.setUsername(username);
        user.setPassword(
                passwordEncoder.encode(
                        signupRequest.getPassword()
                )
        );
        user.setRole("USER");
        user.setFailedLoginAttempts(0);
        user.setLocked(false);

        userRepository.save(user);
    }

    @Override
    public AuthValidationResponse validate(String token) {

        // Check whether JWT is valid
        if (!jwtService.isTokenValid(token)) {
            throw new InvalidTokenException(
                    "Invalid JWT token"
            );
        }

        // Get token expiration
        Instant expiresAt =
                jwtService.extractExpiration(token);

        // Check expiration
        if (expiresAt.isBefore(Instant.now())) {
            throw new TokenExpiredException(
                    "JWT token has expired"
            );
        }

        // Check whether token is still active
        if (!tokenStoreService.isTokenActive(token)) {
            throw new InvalidTokenException(
                    "Token has been revoked"
            );
        }

        // Extract username from JWT
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

    @Override
    public LoginResponse refreshAccessToken(String refreshToken) {

        // Validate the refresh token
        RefreshToken storedRefreshToken =
                refreshTokenService.validateRefreshToken(refreshToken);

        // Get the username from the refresh token
        String username =
                jwtService.extractUsername(refreshToken);

        // Get the user from PostgreSQL
        User user = userRepository
                .findByUsername(username)
                .orElseThrow(() ->
                        new InvalidCredentialsException(
                                "User not found"
                        )
                );

        // Generate a new access token
        String accessToken = jwtService.generateToken(
                user.getUsername(),
                user.getRole()
        );

        // Access token issue time
        Instant issuedAt = Instant.now();

        // Access token expiry time
        Instant expiresAt =
                jwtService.extractExpiration(accessToken);

        // Store new access token
        TokenMetadata tokenMetadata = new TokenMetadata(
                accessToken,
                user.getUsername(),
                issuedAt,
                expiresAt
        );

        tokenStoreService.storeToken(tokenMetadata);

        // Return new access token
        return new LoginResponse(
                accessToken,
                refreshToken,
                user.getUsername(),
                expiresAt
        );
    }
}
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
    public LoginResponse authenticate(LoginRequest loginRequest) throws InterruptedException {

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


        user.setFailedLoginAttempts(0);
        userRepository.save(user);


        String accessToken = jwtService.generateToken(
                user.getUsername(),
                user.getRole()
        );


        Instant issuedAt = Instant.now();


        Instant expiresAt =
                jwtService.extractExpiration(accessToken);


        TokenMetadata tokenMetadata = new TokenMetadata(
                accessToken,
                user.getUsername(),
                issuedAt,
                expiresAt
        );

        tokenStoreService.storeToken(tokenMetadata);


        RefreshToken refreshToken =
                refreshTokenService.createRefreshToken(
                        user.getUsername()
                );



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

    @Override
    public LoginResponse refreshAccessToken(String refreshToken) {

        RefreshToken storedRefreshToken =
                refreshTokenService.validateRefreshToken(refreshToken);


        String username =
                jwtService.extractUsername(refreshToken);


        User user = userRepository
                .findByUsername(username)
                .orElseThrow(() ->
                        new InvalidCredentialsException(
                                "User not found"
                        )
                );


        String accessToken = jwtService.generateToken(
                user.getUsername(),
                user.getRole()
        );


        Instant issuedAt = Instant.now();


        Instant expiresAt =
                jwtService.extractExpiration(accessToken);


        TokenMetadata tokenMetadata = new TokenMetadata(
                accessToken,
                user.getUsername(),
                issuedAt,
                expiresAt
        );

        tokenStoreService.storeToken(tokenMetadata);


        return new LoginResponse(
                accessToken,
                refreshToken,
                user.getUsername(),
                expiresAt
        );
    }
}
package com.capstone.auth.service;

import com.capstone.auth.model.TokenMetadata;
import com.capstone.auth.repository.TokenRepository;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class TokenStoreService {

    private final TokenRepository tokenRepository;

    public TokenStoreService(TokenRepository tokenRepository) {
        this.tokenRepository = tokenRepository;
    }

    public void storeToken(TokenMetadata tokenMetadata) {
        tokenRepository.save(tokenMetadata);
    }

    public Optional<TokenMetadata> getToken(String token) {
        return tokenRepository.findByToken(token);
    }

    public boolean isTokenActive(String token) {
        return tokenRepository.existsByToken(token);
    }

    public void revokeToken(String token) {
        tokenRepository.deleteByToken(token);
    }
}
package com.capstone.auth.repository;

import com.capstone.auth.model.TokenMetadata;

import java.util.Optional;

public interface TokenRepository{

    void save(TokenMetadata tokenMetadata);

    Optional<TokenMetadata> findByToken(String token);

    boolean existsByToken(String token);

    void deleteByToken(String token);
}
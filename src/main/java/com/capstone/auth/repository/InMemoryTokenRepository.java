package com.capstone.auth.repository;

import com.capstone.auth.model.TokenMetadata;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

@Repository
public class InMemoryTokenRepository implements TokenRepository {

    private final ConcurrentMap<String, TokenMetadata> tokens = new ConcurrentHashMap<>();

    @Override
    public void save(TokenMetadata tokenMetadata) {
        tokens.put(tokenMetadata.getToken(), tokenMetadata);
    }

    @Override
    public Optional<TokenMetadata> findByToken(String token) {
        return Optional.ofNullable(tokens.get(token));
    }

    @Override
    public boolean existsByToken(String token) {
        return tokens.containsKey(token);
    }

    @Override
    public void deleteByToken(String token) {
        tokens.remove(token);
    }
}
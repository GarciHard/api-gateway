package com.garcihard.gateway.security.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

import java.security.PublicKey;

@Component
public class JwtUtil {

    private final PublicKey publicKey;

    public JwtUtil(@Value("${jwt.secret.path}")Resource publicKeyResource) throws Exception {
        this.publicKey = KeyReaderUtil.readPublicKey(publicKeyResource.getInputStream());
    }

    public Claims validateAndParseClaims(String token) {
        if (token == null || token.isBlank()) {
            throw new IllegalArgumentException("Token cannot be null or blank.");
        }
        return Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}

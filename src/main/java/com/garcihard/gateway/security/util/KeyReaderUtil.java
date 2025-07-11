package com.garcihard.gateway.security.util;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class KeyReaderUtil {
    public static PublicKey readPublicKey(InputStream inputStream) throws Exception{
        byte[] keyBytes = getAllBytes(inputStream);
        String publicKeyPEM = new String(keyBytes, StandardCharsets.UTF_8)
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PUBLIC KEY-----", "");

        byte[] decoded = Base64.getDecoder().decode(publicKeyPEM);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(new X509EncodedKeySpec(decoded));
    }

    private static byte[] getAllBytes(InputStream inputStream) throws IOException{
        if (inputStream == null) {
            throw new IllegalArgumentException("Public Secret not found");
        }
        return inputStream.readAllBytes();
    }
}

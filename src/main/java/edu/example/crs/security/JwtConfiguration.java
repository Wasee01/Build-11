package edu.example.crs.security;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtAudienceValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

@Configuration(proxyBeanMethods = false)
class JwtConfiguration {

    static final String ISSUER = "secured-crs";
    static final String AUDIENCE = "secured-crs-api";
    static final MacAlgorithm SIGNING_ALGORITHM = MacAlgorithm.HS256;

    @Bean
    SecretKey jwtSigningKey(@Value("${CRS_JWT_SECRET:}") String configuredSecret) {
        byte[] key;
        if (configuredSecret.isEmpty()) {
            key = new byte[32];
            new SecureRandom().nextBytes(key);
        } else {
            key = Base64.getDecoder().decode(configuredSecret);
        }

        if (key.length < 32) {
            throw new IllegalArgumentException("CRS_JWT_SECRET must decode to at least 32 bytes.");
        }

        return new SecretKeySpec(key, "HmacSHA256");
    }

    @Bean
    JwtEncoder jwtEncoder(SecretKey signingKey) {
        return NimbusJwtEncoder.withSecretKey(signingKey).algorithm(SIGNING_ALGORITHM).build();
    }

    @Bean
    JwtDecoder jwtDecoder(SecretKey signingKey) {
        var decoder = NimbusJwtDecoder.withSecretKey(signingKey).macAlgorithm(SIGNING_ALGORITHM).build();
        decoder.setJwtValidator(JwtValidators.createDefaultWithValidators(List.of(
                new JwtIssuerValidator(ISSUER),
                new JwtAudienceValidator(AUDIENCE))));
        return decoder;
    }
}

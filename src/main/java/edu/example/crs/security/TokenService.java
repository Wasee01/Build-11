package edu.example.crs.security;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
class TokenService {

    private static final Duration LIFETIME = Duration.ofMinutes(15);

    private final AuthenticationManager authentication;
    private final JwtEncoder encoder;

    TokenService(AuthenticationManager authentication, JwtEncoder encoder) {
        this.authentication = authentication;
        this.encoder = encoder;
    }

    TokenController.TokenResponse issue(TokenController.Credentials credentials) {
        if (credentials.username() == null || credentials.username().isBlank()
                || credentials.password() == null || credentials.password().isEmpty()
                || credentials.password().getBytes(StandardCharsets.UTF_8).length > 72) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Provide a username and a valid password.");
        }

        var principal = authentication.authenticate(UsernamePasswordAuthenticationToken
                .unauthenticated(credentials.username(), credentials.password()));
        var roles = principal.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .filter(authority -> authority.startsWith("ROLE_"))
                .map(authority -> authority.substring("ROLE_".length()))
                .toList();

        Instant now = Instant.now();
        var claims = JwtClaimsSet.builder()
                .issuer(JwtConfiguration.ISSUER)
                .audience(List.of(JwtConfiguration.AUDIENCE))
                .subject(principal.getName())
                .issuedAt(now)
                .expiresAt(now.plus(LIFETIME))
                .claim("roles", roles)
                .build();

        var header = JwsHeader.with(JwtConfiguration.SIGNING_ALGORITHM).build();
        String token = encoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
        return new TokenController.TokenResponse(token, "Bearer", LIFETIME.toSeconds());
    }
}

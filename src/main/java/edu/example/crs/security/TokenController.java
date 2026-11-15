package edu.example.crs.security;

import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
class TokenController {

    private final TokenService tokens;

    TokenController(TokenService tokens) {
        this.tokens = tokens;
    }

    @PostMapping("/token")
    ResponseEntity<TokenResponse> token(@RequestBody Credentials credentials) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(tokens.issue(credentials));
    }

    record Credentials(String username, String password) {
    }

    record TokenResponse(String accessToken, String tokenType, long expiresIn) {
    }
}

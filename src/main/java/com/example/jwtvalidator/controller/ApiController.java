
package com.example.jwtvalidator.controller;

import java.util.Map;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ApiController {

    // Public API
    @GetMapping("/api/public")
    public Map<String, String> publicEndpoint() {

        return Map.of(
            "message", "Public API accessed successfully"
        );
    }

    // Protected API
    @GetMapping("/api/secure")
    public Map<String, Object> secureEndpoint(
            @AuthenticationPrincipal Jwt jwt) {

        return Map.of(
            "message", "JWT is valid. Access granted",
            "subject", jwt.getSubject(),
            "issuer", jwt.getIssuer().toString(),
            "expiresAt", jwt.getExpiresAt().toString()
        );
    }
}

package io.assignment.auth.service;

import com.nimbusds.jose.JOSEException;
import io.assignment.auth.dto.MfaSetupDetails;
import io.assignment.auth.dto.UserPrincipal;
import jakarta.servlet.http.HttpServletRequest;

import io.assignment.auth.dto.TokenPair;

public interface AuthService {
    void signup(String email, String rawPassword);
    TokenPair login(String email, String rawPassword, String mfaCode, String userAgent, String ip) throws JOSEException;
    TokenPair rotate(String refreshToken, String userAgent, String ip) throws JOSEException;
    void logout(String accessToken, String refreshToken);
    MfaSetupDetails setupMfa(Long userId);
    TokenPair issueTokensForUser(UserPrincipal principal, String userAgent, String ip) throws JOSEException;

    default String extractRefreshFrom(HttpServletRequest req) {
        if (req == null) throw new IllegalStateException("No request context");
        String hdr = req.getHeader("X-Refresh-Token");
        if (hdr != null && !hdr.isBlank()) return hdr;
        String auth = req.getHeader("Authorization");
        if (auth != null && auth.startsWith("Bearer ")) return auth.substring(7);
        if (req.getCookies() != null) {
            for (var c : req.getCookies()) if ("refreshToken".equalsIgnoreCase(c.getName())) return c.getValue();
        }
        throw new IllegalStateException("Refresh token not found");
    }
}

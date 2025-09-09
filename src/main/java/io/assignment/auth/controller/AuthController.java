package io.assignment.auth.controller;
import com.nimbusds.jose.JOSEException;
import io.assignment.auth.api.AuthApi;

import io.assignment.auth.dto.AuthLoginPost200Response;
import io.assignment.auth.dto.AuthLoginPostRequest;
import io.assignment.auth.dto.AuthSignupPostRequest;
import io.assignment.auth.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

@RestController
@RequiredArgsConstructor
public class AuthController implements AuthApi {
    private final AuthService authService;

    private HttpServletRequest currentRequest() {
        var attrs = (ServletRequestAttributes)RequestContextHolder.getRequestAttributes();
        return attrs != null ? attrs.getRequest() : null;
    }

    private HttpServletResponse currentResponse() {
        var attrs = (ServletRequestAttributes)RequestContextHolder.getRequestAttributes();
        return attrs != null ? attrs.getResponse() : null;
    }

    private String getIp() {
        var req = currentRequest();
        var isReq = req != null;
        return isReq ? req.getRemoteAddr() : null;
    }

    private String getUa() {
        var req = currentRequest();
        var isReq = req != null;
        return isReq ? req.getHeader("User-Agent") : null;
    }

    @Override
    public ResponseEntity<Void> authSignupPost(@Valid AuthSignupPostRequest body) {
        authService.signup(body.getEmail(), body.getPassword());
        return ResponseEntity.status(201).build();
    }

    @Override
    public ResponseEntity<AuthLoginPost200Response> authLoginPost(@Valid AuthLoginPostRequest body) {
        try {
            var tknPair = authService.login(
                    body.getEmail(),
                    body.getPassword(),
                    body.getMfaCode(),
                    getUa(),
                    getIp()
            );

            var res = new AuthLoginPost200Response()
                    .accessToken(tknPair.getAccessToken())
                    .refreshToken(tknPair.getRefreshToken());
            return ResponseEntity.ok(res);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public ResponseEntity<Void> authRefreshPost() {
        try {
            var refresh = authService.extractRefreshFrom(currentRequest());
            authService.rotate(refresh, getUa(), getIp());
            return ResponseEntity.noContent().build();
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public ResponseEntity<Void> authLogoutPost() {
        var req = currentRequest();
        var res = currentResponse();

        // Access Token 추출
        String accessToken = null;
        String authHeader = req.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            accessToken = authHeader.substring(7);
        }

        var refreshToken = authService.extractRefreshFrom(req);
        authService.logout(accessToken, refreshToken);

        if (res != null) {
            var clear = ResponseCookie.from("refreshToken", "")
                    .httpOnly(true)
                    .secure(true)
                    .path("/")
                    .sameSite("Strict")
                    .maxAge(0)
                    .build();
            res.addHeader(HttpHeaders.SET_COOKIE, clear.toString());
        }

        return ResponseEntity.noContent().build();
    }
}

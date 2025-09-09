package io.assignment.auth.token;

import com.nimbusds.jose.JOSEException;
import io.assignment.auth.dto.UserPrincipal;
import io.assignment.auth.service.AuthService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

@Component
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final AuthService authService;

    @Value("${security.refresh.ttl-days:30}")
    private int refreshTtlDays;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        var principal = (UserPrincipal) authentication.getPrincipal();
        var userAgent = request.getHeader("User-Agent");
        var ip = request.getRemoteAddr();

        try {
            var tokenPair = authService.issueTokensForUser(principal, userAgent, ip);

            var cookie = new Cookie("refreshToken", tokenPair.getRefreshToken());
            cookie.setHttpOnly(true);
            cookie.setSecure(request.isSecure());
            cookie.setPath("/");
            cookie.setMaxAge((int) TimeUnit.DAYS.toSeconds(refreshTtlDays));
            response.addCookie(cookie);

            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            response.getWriter().write(String.format("{\"accessToken\": \"%s\"}", tokenPair.getAccessToken()));

            clearAuthenticationAttributes(request);

        } catch (JOSEException e) {
            throw new ServletException("Error issuing tokens after social login", e);
        }
    }
}

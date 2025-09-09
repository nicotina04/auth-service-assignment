package io.assignment.auth.token;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import io.assignment.auth.dto.UserPrincipal;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {
    private final JWKSource<SecurityContext> jwkSource;
    private final JwtService jwtService;
    private final RedisTemplate<String, String> redisTemplate;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        var auth = request.getHeader("Authorization");

        if (auth == null || !auth.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        var token = auth.substring(7);
        try {
            var claims = jwtService.verify(token, jwkSource);

            var jti = claims.getJWTID();
            if (Boolean.TRUE.equals(redisTemplate.hasKey("jti:" + jti))) {
                filterChain.doFilter(request, response);
                return;
            }

            Long uid = Long.valueOf(claims.getSubject());
            @SuppressWarnings("unchecked")
            var rolesClaim = (List<String>) claims.getClaim("roles");
            var roles = rolesClaim != null ? rolesClaim : List.<String>of();
            var mfaVerified = Boolean.TRUE.equals(claims.getBooleanClaim("mfa"));
            var authorities = roles.stream().map(r -> new SimpleGrantedAuthority("ROLE_" + r)).toList();
            var principal = new UserPrincipal(uid, claims.getStringClaim("email"), roles, mfaVerified);
            var authentication = new UsernamePasswordAuthenticationToken(principal, null, authorities);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (Exception e) {
            // Ignore invalid/expired tokens and continue the chain
        }

        filterChain.doFilter(request, response);
    }

    // Swagger 관련 경로는 필터링 제외
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();

        return path.startsWith("/v3/api-docs") ||
                path.startsWith("/swagger-ui") ||
                path.startsWith("/swagger-resources") ||
                path.equals("/openapi.yaml");
    }
}


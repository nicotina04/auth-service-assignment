package io.assignment.auth.service;

import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import io.assignment.auth.domain.RefreshToken;
import io.assignment.auth.domain.User;
import io.assignment.auth.domain.UserStatus;
import io.assignment.auth.dto.MfaSetupDetails;
import io.assignment.auth.dto.TokenPair;
import io.assignment.auth.dto.UserPrincipal;
import io.assignment.auth.repository.RefreshTokenRepository;
import io.assignment.auth.repository.UserRepository;
import io.assignment.auth.repository.UserRoleRepository;
import io.assignment.auth.token.JwtService;
import io.assignment.auth.token.TokenHasher;
import io.assignment.auth.token.TokenIssuer;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.Base64;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Transactional
public class AuthServiceImpl implements AuthService {
    private static final Logger log = LoggerFactory.getLogger(AuthServiceImpl.class);
    private final UserRepository users;
    private final UserRoleRepository roles;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenIssuer tokenIssuer;
    private final TokenHasher tokenHasher;
    private final Clock clock;
    private final RedisTemplate<String, String> redisTemplate;
    private final JwtService jwtService;
    private final JWKSource<SecurityContext> jwkSource;
    private final TimeBasedOneTimePasswordGenerator totpGenerator;
    private final KeyGenerator secretKeyGenerator;
    private final AuthenticationManager authenticationManager;


    @Value("${security.refresh.ttl-days:30}")
    private int refreshTtlDays;

    @Value("${spring.application.name:AuthService}")
    private String appName;

    @Override
    public void signup(String email, String rawPassword) {
        users.findByEmailIgnoreCase(email).ifPresent(u -> {
            throw new IllegalArgumentException("email already exists.");
        });

        var user = new User();
        user.setEmail(email.trim().toLowerCase());
        user.setPasswordHash(passwordEncoder.encode(rawPassword));
        user.setStatus(UserStatus.ACTIVE);
        user.setMfaEnabled(false);
        user.setCreatedAt(OffsetDateTime.now());
        user.setUpdatedAt(OffsetDateTime.now());
        users.save(user);
        roles.save(new io.assignment.auth.domain.UserRole(user.getId(), io.assignment.auth.domain.Role.PARENT));
    }

    @Override
    public TokenPair login(String email, String rawPassword, String mfaCode, String userAgent, String ip) throws JOSEException {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(email, rawPassword)
        );
        UserPrincipal principal = (UserPrincipal) authentication.getPrincipal();
        User user = users.findById(principal.getId()).orElseThrow(); // User is guaranteed to exist after successful authentication

        var userRoles = principal.getAuthorities().stream()
                .map(a -> a.getAuthority().replace("ROLE_", ""))
                .collect(Collectors.toSet());

        var isAdminish = userRoles.stream().anyMatch(r -> r.equals("ADMIN") || r.equals("MASTER"));
        var mfaVerified = false;
        if (user.isMfaEnabled()) {
            if (mfaCode == null || mfaCode.isBlank()) {
                throw new IllegalArgumentException("mfa_required");
            }

            try {
                if (!verifyTotp(user.getMfaSecret(), mfaCode)) {
                    throw new IllegalArgumentException("invalid_mfa");
                }
            } catch (InvalidKeyException e) {
                throw new RuntimeException("MFA validation failed due to internal key error", e);
            }
            mfaVerified = true;
        } else {
            mfaVerified = !isAdminish;
        }

        return issueTokens(user, mfaVerified, userAgent, ip);
    }

    @Override
    public TokenPair issueTokensForUser(UserPrincipal principal, String userAgent, String ip) throws JOSEException {
        var user = users.findById(principal.getId())
                .orElseThrow(() -> new IllegalStateException("user_not_found"));
        return issueTokens(user, principal.isMfaVerified(), userAgent, ip);
    }

    @Override
    public TokenPair rotate(String refreshToken, String userAgent, String ip) throws JOSEException {
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new IllegalArgumentException("missing_refresh");
        }
        var now = OffsetDateTime.now(clock);
        String hash = tokenHasher.hash(refreshToken);

        var old = refreshTokenRepository.findByTokenHashAndRevokedAtIsNullAndExpiresAtAfter(hash, now)
                .orElseThrow(() -> new IllegalArgumentException("invalid_or_revoked_refresh"));

        old.setRevokedAt(now);
        refreshTokenRepository.save(old);

        String newRefresh = RefreshToken.randomToken();
        String newHash = tokenHasher.hash(newRefresh);

        var rt = new RefreshToken();
        rt.setUserId(old.getUserId());
        rt.setTokenHash(newHash);
        rt.setIssuedAt(now);
        rt.setExpiresAt(now.plusDays(refreshTtlDays));
        rt.setRotatedFrom(old.getId());
        rt.setUserAgent(userAgent);
        rt.setIp(ip);
        refreshTokenRepository.save(rt);

        var user = users.findById(old.getUserId())
                .orElseThrow(() -> new IllegalStateException("user_not_found"));
        var userRoles = roles.findRoleNamesByUserId(user.getId());
        boolean isAdminish = userRoles.stream().anyMatch(r -> r.equals("ADMIN") || r.equals("MASTER"));
        boolean mfaVerified = user.isMfaEnabled() || !isAdminish;
        String access = tokenIssuer.issueAccess(user.getId(), user.getEmail(), userRoles, mfaVerified);

        return new TokenPair(access, newRefresh);
    }

    @Override
    public void logout(String accessToken, String refreshToken) {
        try {
            var claims = jwtService.verify(accessToken, jwkSource);
            var jti = claims.getJWTID();
            var exp = claims.getExpirationTime().toInstant();
            var now = OffsetDateTime.now(clock).toInstant();
            var remaining = Duration.between(now, exp);
            if (!remaining.isNegative()) {
                redisTemplate.opsForValue().set("jti:" + jti, "logout", remaining);
            }
        } catch (ParseException | JOSEException | com.nimbusds.jose.proc.BadJOSEException e) {
            log.warn("Failed to process token during logout for blacklisting. Token might be invalid or expired. Error: {}", e.getMessage());
        }

        if (refreshToken == null || refreshToken.isBlank()) return;
        var now = OffsetDateTime.now(clock);
        String hash = tokenHasher.hash(refreshToken);

        refreshTokenRepository.findByTokenHashAndRevokedAtIsNullAndExpiresAtAfter(hash, now).ifPresent(rt -> {
            rt.setRevokedAt(now);
            refreshTokenRepository.save(rt);
        });
    }

    @Override
    public MfaSetupDetails setupMfa(Long userId) {
        var user = users.findById(userId)
                .orElseThrow(() -> new IllegalStateException("user_not_found"));

        SecretKey secretKey = secretKeyGenerator.generateKey();
        String base64Secret = Base64.getEncoder().encodeToString(secretKey.getEncoded());

        user.setMfaSecret(base64Secret);
        user.setMfaEnabled(true);
        user.setUpdatedAt(OffsetDateTime.now(clock));
        users.save(user);

        String qrLabel = String.format("%s:%s", appName, user.getEmail());
        return new MfaSetupDetails(base64Secret, qrLabel);
    }

    private boolean verifyTotp(String base64Secret, String code) throws InvalidKeyException {
        if (base64Secret == null || base64Secret.isBlank() || code == null || code.isBlank()) {
            return false;
        }
        byte[] keyBytes = Base64.getDecoder().decode(base64Secret);
        SecretKey secretKey = new SecretKeySpec(keyBytes, 0, keyBytes.length, "HmacSHA256");

        try {
            var now = Instant.now(clock);
            int userCode = Integer.parseInt(code);

            if (totpGenerator.generateOneTimePassword(secretKey, now) == userCode) {
                return true;
            }
            if (totpGenerator.generateOneTimePassword(secretKey, now.minus(totpGenerator.getTimeStep())) == userCode) {
                return true;
            }
            return totpGenerator.generateOneTimePassword(secretKey, now.plus(totpGenerator.getTimeStep())) == userCode;

        } catch (NumberFormatException e) {
            return false;
        }
    }

    private TokenPair issueTokens(User user, boolean mfaVerified, String userAgent, String ip) throws JOSEException {
        var userRoles = roles.findRoleNamesByUserId(user.getId());
        var accessToken = tokenIssuer.issueAccess(user.getId(), user.getEmail(), userRoles, mfaVerified);
        var refresh = RefreshToken.randomToken();
        var refreshHash = tokenHasher.hash(refresh);

        var now = OffsetDateTime.now(clock);
        var rt = new RefreshToken();
        rt.setUserId(user.getId());
        rt.setTokenHash(refreshHash);
        rt.setIssuedAt(now);
        rt.setExpiresAt(now.plusDays(refreshTtlDays));
        rt.setRotatedFrom(null);
        rt.setUserAgent(userAgent);
        rt.setIp(ip);
        refreshTokenRepository.save(rt);

        return new TokenPair(accessToken, refresh);
    }
}

package io.assignment.auth.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import io.assignment.auth.token.TokenIssuer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Clock;

@Configuration
public class TokenConfig {

    @Value("classpath:jwks.json")
    private Resource jwksResource;

    @Value("${security.jwt.issuer:AuthService}")
    private String issuer;

    @Value("${security.jwt.audience:client}")
    private String audience;

    @Value("${security.jwt.access-ttl-seconds:3600}")
    private long accessTtlSeconds;

    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }

    @Bean
    public JWKSet jwkSet() throws IOException, ParseException {
        String jwksJson = jwksResource.getContentAsString(StandardCharsets.UTF_8);
        return JWKSet.parse(jwksJson);
    }

    @Bean
    public RSAKey signingKey(JWKSet jwkSet) throws ParseException {
        // JWKSet에서 서명(use: "sig")용 키를 찾아 반환
        return jwkSet.getKeys().stream()
                .filter(jwk -> "sig".equals(jwk.getKeyUse().getValue()))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("No signing key found in jwks.json"))
                .toRSAKey();
    }

    @Bean
    public TokenIssuer tokenIssuer(RSAKey signingKey) {
        return new TokenIssuer(signingKey, issuer, audience, accessTtlSeconds);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource(JWKSet jwkSet) {
        return new ImmutableJWKSet<>(jwkSet.toPublicJWKSet());
    }
}

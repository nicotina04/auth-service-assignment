package io.assignment.auth.token;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

@RequiredArgsConstructor
public class TokenIssuer {
    private final RSAKey signinKey;
    private final String issuer;
    private final String audience;
    private final long accessTtlSeconds;

    public String issueAccess(Long uid, String email, List<String> roles, boolean mfaVerified) throws JOSEException {
        var now = Instant.now();

        var header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(signinKey.getKeyID())
                .type(JOSEObjectType.JWT)
                .build();

        var claims = new JWTClaimsSet.Builder()
                .subject(String.valueOf(uid))
                .claim("email", email)
                .claim("roles", roles)
                .claim("mfa", mfaVerified)
                .issuer(issuer)
                .audience(audience)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(accessTtlSeconds)))
                .jwtID(UUID.randomUUID().toString())
                .build();

        var jwt = new SignedJWT(header, claims);
        var signer = new RSASSASigner(signinKey);
        jwt.sign(signer);
        return jwt.serialize();
    }

    public JWKSet getPublicJwks() {
        var pub = signinKey.toPublicJWK();
        return new JWKSet(pub);
    }
}

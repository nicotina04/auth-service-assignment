package io.assignment.auth.token;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.springframework.stereotype.Component;

import java.text.ParseException;
import java.util.Objects;

@Component
public class JwtService {

    public JWTClaimsSet verify(String token, JWKSource<SecurityContext> jwkSource) throws BadJOSEException, JOSEException, ParseException {
        Objects.requireNonNull(token, "token must not be null");
        Objects.requireNonNull(jwkSource, "jwkSource must not be null");

        SignedJWT signed = SignedJWT.parse(token);

        if (signed.getHeader().getAlgorithm() == null) {
            throw new BadJOSEException("Unsupported or missing JWS algorithm in header");
        }

        JWSAlgorithm alg = signed.getHeader().getAlgorithm();

        ConfigurableJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(alg, jwkSource);
        processor.setJWSKeySelector(keySelector);

        return processor.process(signed, null);
    }
}

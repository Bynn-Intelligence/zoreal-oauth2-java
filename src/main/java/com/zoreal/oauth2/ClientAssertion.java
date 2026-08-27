package com.zoreal.oauth2;

import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * Builds and signs the RFC 7523 {@code client_assertion} for
 * private_key_jwt. The provider is strict on the shape and this mirrors it
 * exactly: {@code iss} and {@code sub} are the client id, {@code aud} is the
 * issuer's token endpoint, the lifetime is 60 seconds (the provider rejects
 * {@code exp > now+60} and {@code iat < now-60}), and {@code jti} is fresh
 * random per assertion because the provider enforces single use.
 */
final class ClientAssertion {

    static final String TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    static final long LIFETIME_SECONDS = 60;

    private ClientAssertion() {
    }

    /** A freshly signed compact JWT, new {@code jti} every call. */
    static String build(String clientId, String issuer, ClientAuth.PrivateKeyJwt auth) {
        Instant now = Instant.now();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(clientId)
                .subject(clientId)
                .audience(issuer + "/token")
                .expirationTime(Date.from(now.plusSeconds(LIFETIME_SECONDS)))
                .issueTime(Date.from(now))
                .jwtID(UUID.randomUUID().toString())
                .build();

        PrivateKey key = auth.key();
        JWSAlgorithm algorithm = key instanceof ECPrivateKey ? JWSAlgorithm.ES256 : JWSAlgorithm.RS256;
        JWSHeader.Builder header = new JWSHeader.Builder(algorithm);
        if (auth.kid() != null && !auth.kid().isBlank()) {
            header.keyID(auth.kid());
        }

        SignedJWT jwt = new SignedJWT(header.build(), claims);
        try {
            JWSSigner signer = key instanceof ECPrivateKey ec ? new ECDSASigner(ec) : new RSASSASigner(key);
            jwt.sign(signer);
        } catch (JOSEException e) {
            // A curve other than P-256 lands here: ES256 needs P-256 and the
            // provider accepts nothing wider.
            throw new ConfigurationException(
                    "the private_key_jwt key cannot sign ES256 or RS256: " + e.getMessage(), e);
        }
        return jwt.serialize();
    }
}

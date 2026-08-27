package com.zoreal.oauth2;

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Offline verification tests: the JWKS is injected through a JwksSource
 * double, so nothing here touches the network.
 */
class VerifyIdTokenTest {

    private static final String ISSUER = "https://id.zoreal.example";
    private static final String CLIENT_ID = "ast_test_client";

    private ECKey key;
    private ZorealOAuth2Client client;

    @BeforeEach
    void setUp() throws JOSEException {
        key = new ECKeyGenerator(Curve.P_256).keyID("k1").generate();
        client = ZorealOAuth2Client.builder()
                .clientId(CLIENT_ID)
                .issuer(ISSUER)
                .jwksSource(new StaticJwksSource(new JWKSet(key.toPublicJWK())))
                .build();
    }

    private JWTClaimsSet.Builder baseClaims() {
        long now = System.currentTimeMillis();
        return new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .subject("7QK3-9F2M-XR84-B5NP")
                .audience(CLIENT_ID)
                .expirationTime(new Date(now + 120_000))
                .issueTime(new Date(now))
                .claim("nonce", "n-1")
                .claim("acr", "zoreal.device");
    }

    private String sign(JWTClaimsSet claims) throws JOSEException {
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(key.getKeyID()).build(), claims);
        jwt.sign(new ECDSASigner(key));
        return jwt.serialize();
    }

    @Test
    void validTokenVerifiesAndReturnsClaims() throws JOSEException {
        Map<String, Object> claims = client.verifyIdToken(sign(baseClaims().build()), "n-1");
        assertEquals("7QK3-9F2M-XR84-B5NP", claims.get("sub"));
        assertEquals("zoreal.device", claims.get("acr"));
    }

    @Test
    void nonceMismatchIsRefused() throws JOSEException {
        String token = sign(baseClaims().build());
        assertThrows(VerificationException.class, () -> client.verifyIdToken(token, "other"));
    }

    @Test
    void nonceIsNotCheckedWhenCallerHasNone() throws JOSEException {
        assertNotNull(client.verifyIdToken(sign(baseClaims().build())));
    }

    @Test
    void wrongAudienceIsRefused() throws JOSEException {
        String token = sign(baseClaims().audience("ast_other").build());
        assertThrows(VerificationException.class, () -> client.verifyIdToken(token));
    }

    @Test
    void wrongIssuerIsRefused() throws JOSEException {
        String token = sign(baseClaims().issuer("https://evil.example").build());
        assertThrows(VerificationException.class, () -> client.verifyIdToken(token));
    }

    @Test
    void expiredTokenIsRefused() throws JOSEException {
        String token = sign(baseClaims().expirationTime(new Date(System.currentTimeMillis() - 5_000)).build());
        assertThrows(VerificationException.class, () -> client.verifyIdToken(token));
    }

    @Test
    void foreignKeyIsRefused() throws JOSEException {
        // Signed by a different P-256 key that claims the trusted key's kid:
        // the lookup succeeds and the signature check has to be what refuses it.
        ECKey foreign = new ECKeyGenerator(Curve.P_256).keyID(key.getKeyID()).generate();
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(key.getKeyID()).build(), baseClaims().build());
        jwt.sign(new ECDSASigner(foreign));
        String token = jwt.serialize();
        assertThrows(VerificationException.class, () -> client.verifyIdToken(token));
    }

    @Test
    void unknownKidIsRefusedAfterOneRefetch() throws JOSEException {
        ECKey foreign = new ECKeyGenerator(Curve.P_256).keyID("k-unknown").generate();
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("k-unknown").build(), baseClaims().build());
        jwt.sign(new ECDSASigner(foreign));
        String token = jwt.serialize();
        assertThrows(VerificationException.class, () -> client.verifyIdToken(token));
    }

    @Test
    void nonEs256AlgorithmIsRefused() throws JOSEException {
        // Even a key present in the JWKS must not get its RS256 token
        // through: the refusal is on the algorithm, before any key lookup.
        RSAKey rsa = new RSAKeyGenerator(2048).keyID("r1").generate();
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("r1").build(), baseClaims().build());
        jwt.sign(new RSASSASigner(rsa));
        String token = jwt.serialize();
        VerificationException refusal =
                assertThrows(VerificationException.class, () -> client.verifyIdToken(token));
        assertTrue(refusal.getMessage().contains("ES256"));
    }

    @Test
    void unknownKidInvalidatesAndRefetchesOnce() throws JOSEException {
        // The stale source has no keys; refresh() serves the real set. A
        // token naming an unseen kid must trigger exactly one refetch and
        // then verify.
        AtomicInteger refreshes = new AtomicInteger();
        JWKSet fresh = new JWKSet(key.toPublicJWK());
        JwksSource rotating = new JwksSource() {
            @Override
            public JWKSet get() {
                return new JWKSet(List.of());
            }

            @Override
            public JWKSet refresh() {
                refreshes.incrementAndGet();
                return fresh;
            }
        };
        ZorealOAuth2Client rotated = ZorealOAuth2Client.builder()
                .clientId(CLIENT_ID)
                .issuer(ISSUER)
                .jwksSource(rotating)
                .build();
        Map<String, Object> claims = rotated.verifyIdToken(sign(baseClaims().build()), "n-1");
        assertEquals("7QK3-9F2M-XR84-B5NP", claims.get("sub"));
        assertEquals(1, refreshes.get());
    }
}

package com.zoreal.oauth2;

import java.util.Date;
import java.util.Map;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The assurance floor at verification: the request was advisory, the signed
 * claim is the proof, and this is the check. Offline, like VerifyIdTokenTest:
 * the JWKS is injected, nothing touches the network.
 */
class AcrVerifyTest {

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

    private String token(String acr) throws JOSEException {
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .subject("s")
                .audience(CLIENT_ID)
                .expirationTime(new Date(System.currentTimeMillis() + 120_000));
        if (acr != null) {
            claims.claim("acr", acr);
        }
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(key.getKeyID()).build(), claims.build());
        jwt.sign(new ECDSASigner(key));
        return jwt.serialize();
    }

    @Test
    void equalAcrSatisfies() throws JOSEException {
        assertNotNull(client.verifyIdToken(token("zoreal.live"), null, "zoreal.live"));
    }

    @Test
    void strongerAcrSatisfies() throws JOSEException {
        assertNotNull(client.verifyIdToken(token("zoreal.live"), null, "zoreal.device"));
    }

    @Test
    void weakerAcrIsRefused() throws JOSEException {
        String token = token("zoreal.device");
        VerificationException refusal = assertThrows(VerificationException.class,
                () -> client.verifyIdToken(token, null, "zoreal.live"));
        // The message names both values and never the token itself.
        assertTrue(refusal.getMessage().contains("zoreal.device"));
        assertTrue(refusal.getMessage().contains("zoreal.live"));
    }

    @Test
    void missingAcrIsRefusedWhenRequired() throws JOSEException {
        String token = token(null);
        assertThrows(VerificationException.class,
                () -> client.verifyIdToken(token, null, "zoreal.session"));
    }

    @Test
    void unknownRequiredAcrIsACallerBug() throws JOSEException {
        String token = token("zoreal.live");
        assertThrows(ConfigurationException.class,
                () -> client.verifyIdToken(token, null, "zoreal.liveness"));
    }

    @Test
    void noRequiredAcrChecksNothing() throws JOSEException {
        assertNotNull(client.verifyIdToken(token(null)));
    }

    @Test
    void loginConveniences() {
        Login live = new Login(client, Map.of("acr", "zoreal.live"), "x", null, null);
        assertTrue(live.live());
        assertTrue(live.satisfiesAcr("zoreal.device"));
        assertFalse(live.satisfiesAcr("made.up"));

        Login device = new Login(client, Map.of("acr", "zoreal.device"), "x", null, null);
        assertFalse(device.live());
        assertFalse(device.satisfiesAcr("zoreal.live"));
    }
}

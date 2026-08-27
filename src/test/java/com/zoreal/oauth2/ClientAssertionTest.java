package com.zoreal.oauth2;

import java.util.Base64;
import java.util.Date;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The private_key_jwt assertion the library builds, decoded and checked
 * claim by claim against what the provider enforces.
 */
class ClientAssertionTest {

    private static final String CLIENT_ID = "ast_test_client";
    private static final String ISSUER = "https://id.zoreal.example";

    @Test
    void theEcAssertionCarriesTheRfc7523Shape() throws Exception {
        ECKey key = new ECKeyGenerator(Curve.P_256).keyID("kid-1").generate();
        ClientAuth.PrivateKeyJwt auth = ClientAuth.privateKeyJwt(key.toECPrivateKey(), "kid-1");

        long before = System.currentTimeMillis() / 1000;
        SignedJWT jwt = SignedJWT.parse(ClientAssertion.build(CLIENT_ID, ISSUER, auth));
        long after = System.currentTimeMillis() / 1000;

        assertEquals(JWSAlgorithm.ES256, jwt.getHeader().getAlgorithm());
        assertEquals("kid-1", jwt.getHeader().getKeyID());
        assertTrue(jwt.verify(new ECDSAVerifier(key.toECPublicKey())));

        JWTClaimsSet claims = jwt.getJWTClaimsSet();
        assertEquals(CLIENT_ID, claims.getIssuer());
        assertEquals(CLIENT_ID, claims.getSubject());
        assertTrue(claims.getAudience().contains(ISSUER + "/token"));
        assertNotNull(claims.getJWTID());
        assertTrue(claims.getJWTID().length() >= 16);

        // The provider rejects exp > now+60 and iat < now-60; the assertion
        // has to sit inside that window with nothing to spare.
        long exp = claims.getExpirationTime().getTime() / 1000;
        long iat = claims.getIssueTime().getTime() / 1000;
        assertTrue(exp <= after + ClientAssertion.LIFETIME_SECONDS);
        assertTrue(exp >= before + ClientAssertion.LIFETIME_SECONDS);
        assertTrue(iat >= before);
        assertTrue(iat <= after);
        assertTrue(claims.getExpirationTime().after(new Date()));
    }

    @Test
    void theJtiIsFreshPerAssertion() throws Exception {
        ECKey key = new ECKeyGenerator(Curve.P_256).generate();
        ClientAuth.PrivateKeyJwt auth = ClientAuth.privateKeyJwt(key.toECPrivateKey(), null);
        String first = SignedJWT.parse(ClientAssertion.build(CLIENT_ID, ISSUER, auth)).getJWTClaimsSet().getJWTID();
        String second = SignedJWT.parse(ClientAssertion.build(CLIENT_ID, ISSUER, auth)).getJWTClaimsSet().getJWTID();
        assertNotEquals(first, second);
    }

    @Test
    void anRsaKeySignsRs256() throws Exception {
        RSAKey key = new RSAKeyGenerator(2048).keyID("rsa-1").generate();
        ClientAuth.PrivateKeyJwt auth = ClientAuth.privateKeyJwt(key.toRSAPrivateKey(), "rsa-1");
        SignedJWT jwt = SignedJWT.parse(ClientAssertion.build(CLIENT_ID, ISSUER, auth));
        assertEquals(JWSAlgorithm.RS256, jwt.getHeader().getAlgorithm());
        assertTrue(jwt.verify(new RSASSAVerifier(key.toRSAPublicKey())));
    }

    @Test
    void aPkcs8PemParsesAndSigns() throws Exception {
        ECKey key = new ECKeyGenerator(Curve.P_256).generate();
        String pem = "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes())
                        .encodeToString(key.toECPrivateKey().getEncoded())
                + "\n-----END PRIVATE KEY-----\n";
        ClientAuth.PrivateKeyJwt auth = ClientAuth.privateKeyJwt(pem, "pem-kid");
        SignedJWT jwt = SignedJWT.parse(ClientAssertion.build(CLIENT_ID, ISSUER, auth));
        assertEquals("pem-kid", jwt.getHeader().getKeyID());
        assertTrue(jwt.verify(new ECDSAVerifier(key.toECPublicKey())));
    }

    @Test
    void aJwkStringParsesAndKeepsItsKid() throws Exception {
        ECKey key = new ECKeyGenerator(Curve.P_256).keyID("jwk-kid").generate();
        ClientAuth.PrivateKeyJwt auth = ClientAuth.privateKeyJwt(key.toJSONString());
        SignedJWT jwt = SignedJWT.parse(ClientAssertion.build(CLIENT_ID, ISSUER, auth));
        assertEquals("jwk-kid", jwt.getHeader().getKeyID());
        assertTrue(jwt.verify(new ECDSAVerifier(key.toECPublicKey())));
    }

    @Test
    void aTraditionalOpensslPemIsRefusedWithTheConversionHint() {
        String sec1 = "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----";
        ConfigurationException refusal =
                assertThrows(ConfigurationException.class, () -> ClientAuth.privateKeyJwt(sec1));
        assertTrue(refusal.getMessage().contains("pkcs8"));
    }
}

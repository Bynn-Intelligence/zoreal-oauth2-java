package com.zoreal.oauth2;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.SSLContext;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The exchange and userinfo wire, against a loopback HTTP server: what the
 * form carries, where the secret travels, and how a provider refusal maps
 * onto the error taxonomy. No external network.
 */
class ExchangeAndUserinfoTest {

    private static final String CLIENT_ID = "ast_test_client";

    private HttpServer server;
    private String issuer;

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.start();
        issuer = "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    private ZorealOAuth2Client.Builder client() {
        return ZorealOAuth2Client.builder()
                .clientId(CLIENT_ID)
                .issuer(issuer)
                .jwksSource(new StaticJwksSource(new JWKSet(java.util.List.of())));
    }

    private void respond(HttpExchange exchange, int status, String json) throws IOException {
        byte[] body = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, body.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(body);
        }
    }

    private static Map<String, String> parseForm(String body) {
        Map<String, String> form = new LinkedHashMap<>();
        for (String pair : body.split("&")) {
            String[] parts = pair.split("=", 2);
            form.put(URLDecoder.decode(parts[0], StandardCharsets.UTF_8),
                    parts.length > 1 ? URLDecoder.decode(parts[1], StandardCharsets.UTF_8) : "");
        }
        return form;
    }

    private static final String SUCCESS_BODY = """
            {"id_token": "not-checked-by-exchange", "access_token": "at-1",
             "token_type": "Bearer", "expires_in": 600, "scope": "openid email"}""";

    @Test
    void exchangeReturnsTheTokenResponse() throws Exception {
        AtomicReference<Map<String, String>> seenForm = new AtomicReference<>();
        server.createContext("/token", exchange -> {
            seenForm.set(parseForm(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8)));
            respond(exchange, 200, SUCCESS_BODY);
        });

        TokenResponse tokens = client().build().exchange("code-1", "verifier-1");

        assertEquals("authorization_code", seenForm.get().get("grant_type"));
        assertEquals("code-1", seenForm.get().get("code"));
        assertEquals("verifier-1", seenForm.get().get("code_verifier"));
        assertEquals(CLIENT_ID, seenForm.get().get("client_id"));
        assertEquals("not-checked-by-exchange", tokens.idToken());
        assertEquals("at-1", tokens.accessToken());
        assertEquals("Bearer", tokens.tokenType());
        assertEquals(600L, tokens.expiresIn());
        assertEquals("openid email", tokens.scope());
    }

    @Test
    void theSecretTravelsAsBasicNeverAsAFormField() throws Exception {
        AtomicReference<String> authorization = new AtomicReference<>();
        AtomicReference<Map<String, String>> seenForm = new AtomicReference<>();
        server.createContext("/token", exchange -> {
            authorization.set(exchange.getRequestHeaders().getFirst("Authorization"));
            seenForm.set(parseForm(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8)));
            respond(exchange, 200, SUCCESS_BODY);
        });

        client().auth(ClientAuth.clientSecretBasic("zcs_secret")).build().exchange("code-1", "verifier-1");

        String expected = "Basic " + Base64.getEncoder()
                .encodeToString((CLIENT_ID + ":zcs_secret").getBytes(StandardCharsets.UTF_8));
        assertEquals(expected, authorization.get());
        assertEquals(CLIENT_ID, seenForm.get().get("client_id"));
        assertFalse(seenForm.get().containsKey("client_secret"));
    }

    @Test
    void thePrivateKeyJwtAssertionIsSentAndVerifies() throws Exception {
        ECKey key = new ECKeyGenerator(Curve.P_256).keyID("kid-1").generate();
        AtomicReference<Map<String, String>> seenForm = new AtomicReference<>();
        server.createContext("/token", exchange -> {
            seenForm.set(parseForm(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8)));
            respond(exchange, 200, SUCCESS_BODY);
        });

        client().auth(ClientAuth.privateKeyJwt(key.toECPrivateKey(), "kid-1")).build()
                .exchange("code-1", "verifier-1");

        assertEquals("urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                seenForm.get().get("client_assertion_type"));
        SignedJWT assertion = SignedJWT.parse(seenForm.get().get("client_assertion"));
        assertTrue(assertion.verify(new ECDSAVerifier(key.toECPublicKey())));
        JWTClaimsSet claims = assertion.getJWTClaimsSet();
        assertEquals(CLIENT_ID, claims.getIssuer());
        assertEquals(CLIENT_ID, claims.getSubject());
        assertTrue(claims.getAudience().contains(issuer + "/token"));
    }

    @Test
    void tlsClientAuthSurfacesTheProviders501() throws Exception {
        AtomicReference<Map<String, String>> seenForm = new AtomicReference<>();
        server.createContext("/token", exchange -> {
            seenForm.set(parseForm(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8)));
            respond(exchange, 501, """
                    {"error": "invalid_request", "error_description":
                     "tls_client_auth is not implemented at this endpoint yet; use private_key_jwt or client_secret_basic"}""");
        });

        ZorealOAuth2Client tls = client().auth(ClientAuth.tlsClientAuth(SSLContext.getDefault())).build();
        ExchangeException refusal =
                assertThrows(ExchangeException.class, () -> tls.exchange("code-1", "verifier-1"));

        assertEquals(501, refusal.getStatus());
        assertEquals("invalid_request", refusal.getOauthError());
        assertTrue(refusal.getDescription().contains("not implemented"));
        // The form carries client_id only: the proof is in the handshake, not the body.
        assertEquals(CLIENT_ID, seenForm.get().get("client_id"));
        assertNull(seenForm.get().get("client_assertion"));
    }

    @Test
    void aProviderRefusalSurfacesVerbatim() {
        server.createContext("/token", exchange ->
                respond(exchange, 400, """
                        {"error": "invalid_grant", "error_description": "the code is not valid"}"""));

        ZorealOAuth2Client plain = client().build();
        ExchangeException refusal =
                assertThrows(ExchangeException.class, () -> plain.exchange("code-1", "verifier-1"));

        assertEquals("invalid_grant", refusal.getOauthError());
        assertEquals("the code is not valid", refusal.getDescription());
        assertEquals(400, refusal.getStatus());
    }

    @Test
    void aTokenResponseWithoutAnIdTokenIsRefused() {
        server.createContext("/token", exchange ->
                respond(exchange, 200, """
                        {"access_token": "at-1", "token_type": "Bearer", "expires_in": 600}"""));

        ZorealOAuth2Client plain = client().build();
        ExchangeException refusal =
                assertThrows(ExchangeException.class, () -> plain.exchange("code-1", "verifier-1"));
        assertEquals("server_error", refusal.getOauthError());
    }

    @Test
    void userinfoReadsTheClaimsWithTheBearerToken() {
        AtomicReference<String> authorization = new AtomicReference<>();
        server.createContext("/userinfo", exchange -> {
            authorization.set(exchange.getRequestHeaders().getFirst("Authorization"));
            respond(exchange, 200, """
                    {"sub": "7QK3-9F2M-XR84-B5NP", "email": "holder@example.com", "email_verified": true}""");
        });

        Map<String, Object> claims = client().build().userinfo("at-1");

        assertEquals("Bearer at-1", authorization.get());
        assertEquals("holder@example.com", claims.get("email"));
        assertEquals(Boolean.TRUE, claims.get("email_verified"));
    }

    @Test
    void aUserinfoRefusalIsAUserinfoError() {
        server.createContext("/userinfo", exchange -> {
            exchange.getResponseHeaders().set("WWW-Authenticate",
                    "Bearer error=\"invalid_token\", error_description=\"the access token is not valid\"");
            respond(exchange, 401, """
                    {"error": "invalid_token", "error_description": "the access token is not valid"}""");
        });

        ZorealOAuth2Client plain = client().build();
        UserinfoException refusal =
                assertThrows(UserinfoException.class, () -> plain.userinfo("at-expired"));
        assertTrue(refusal.getMessage().contains("the access token is not valid"));
    }

    @Test
    void authenticateVerifiesTheIdTokenAndMemoizesUserinfo() throws JOSEException {
        ECKey key = new ECKeyGenerator(Curve.P_256).keyID("k1").generate();
        String idToken = signIdToken(key, "n-1");
        AtomicInteger userinfoHits = new AtomicInteger();

        server.createContext("/token", exchange -> respond(exchange, 200, """
                {"id_token": "%s", "access_token": "at-1", "token_type": "Bearer",
                 "expires_in": 600, "scope": "openid email profile.name"}""".formatted(idToken)));
        server.createContext("/userinfo", exchange -> {
            userinfoHits.incrementAndGet();
            respond(exchange, 200, """
                    {"sub": "7QK3-9F2M-XR84-B5NP", "email": "holder@example.com",
                     "email_verified": true, "name": "ANNA LINDQVIST"}""");
        });

        ZorealOAuth2Client full = client()
                .jwksSource(new StaticJwksSource(new JWKSet(key.toPublicJWK())))
                .auth(ClientAuth.clientSecretBasic("zcs_secret"))
                .build();
        Login login = full.authenticate("code-1", "verifier-1", "n-1");

        assertEquals("7QK3-9F2M-XR84-B5NP", login.sub());
        assertEquals("zoreal.live", login.acr());
        // Two reads, one fetch: userinfo is memoized on the Login.
        assertEquals("holder@example.com", login.email().orElseThrow());
        assertEquals("ANNA LINDQVIST", login.name().orElseThrow());
        assertTrue(login.emailVerified());
        assertEquals(1, userinfoHits.get());
    }

    @Test
    void aLoginWithoutAnAccessTokenNeverFetches() throws JOSEException {
        ECKey key = new ECKeyGenerator(Curve.P_256).keyID("k1").generate();
        String idToken = signIdToken(key, null);
        AtomicInteger userinfoHits = new AtomicInteger();

        server.createContext("/token", exchange -> respond(exchange, 200, """
                {"id_token": "%s", "token_type": "Bearer", "expires_in": 600, "scope": "openid"}"""
                .formatted(idToken)));
        server.createContext("/userinfo", exchange -> {
            userinfoHits.incrementAndGet();
            respond(exchange, 200, "{}");
        });

        Login login = client()
                .jwksSource(new StaticJwksSource(new JWKSet(key.toPublicJWK())))
                .build()
                .authenticate("code-1", "verifier-1");

        assertEquals(Map.of(), login.userinfo());
        assertTrue(login.email().isEmpty());
        assertFalse(login.emailVerified());
        assertEquals(0, userinfoHits.get());
    }

    private String signIdToken(ECKey key, String nonce) throws JOSEException {
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .subject("7QK3-9F2M-XR84-B5NP")
                .audience(CLIENT_ID)
                .expirationTime(new Date(System.currentTimeMillis() + 120_000))
                .issueTime(new Date())
                .claim("acr", "zoreal.live");
        if (nonce != null) {
            claims.claim("nonce", nonce);
        }
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(key.getKeyID()).build(), claims.build());
        jwt.sign(new ECDSASigner(key));
        return jwt.serialize();
    }
}

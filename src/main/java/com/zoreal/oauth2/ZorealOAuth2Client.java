package com.zoreal.oauth2;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * The relying-party client. One instance per registered ZOREAL client;
 * immutable and thread-safe, so build it once at boot and share it.
 *
 * <pre>{@code
 * ZorealOAuth2Client zoreal = ZorealOAuth2Client.builder()
 *         .clientId(System.getenv("ZOREAL_CLIENT_ID"))
 *         .auth(ClientAuth.clientSecretBasic(System.getenv("ZOREAL_CLIENT_SECRET")))
 *         .build();
 *
 * Login login = zoreal.authenticate(code, codeVerifier, nonce);
 * login.sub();       // the pairwise subject: your stable user key
 * login.userinfo();  // Tier B claims (email, name, ...), fetched once
 * }</pre>
 */
public final class ZorealOAuth2Client {

    public static final String DEFAULT_ISSUER = "https://id.zoreal.com";
    public static final String VERSION = "0.1.0";

    /**
     * The assurance vocabulary, weakest to strongest. Verification accepts
     * equal or stronger: an RP requiring {@code zoreal.device} is satisfied
     * by a {@code zoreal.live} token, never the reverse.
     */
    public static final Map<String, Integer> ACR_ORDER;

    static {
        Map<String, Integer> order = new LinkedHashMap<>();
        order.put("zoreal.session", 0);
        order.put("zoreal.device", 1);
        order.put("zoreal.live", 2);
        ACR_ORDER = Collections.unmodifiableMap(order);
    }

    private static final String USER_AGENT = "zoreal-oauth2-java/" + VERSION;

    private final String clientId;
    private final String issuer;
    private final ClientAuth auth;
    private final Duration timeout;
    private final HttpClient http;
    private final JwksSource jwksSource;

    private ZorealOAuth2Client(Builder builder) {
        if (isBlank(builder.clientId)) {
            throw new ConfigurationException("client_id is required");
        }
        if (isBlank(builder.issuer)) {
            throw new ConfigurationException("issuer is required");
        }
        this.clientId = builder.clientId;
        this.issuer = stripTrailingSlash(builder.issuer);
        this.auth = builder.auth;
        this.timeout = builder.timeout;

        HttpClient.Builder http = HttpClient.newBuilder().connectTimeout(timeout);
        if (auth instanceof ClientAuth.TlsClientAuth tls) {
            // The certificate and key live in the caller's SSLContext and are
            // presented at the TLS layer on every connection; nothing about
            // them enters the form.
            http.sslContext(tls.sslContext());
        }
        this.http = http.build();
        this.jwksSource = builder.jwksSource != null
                ? builder.jwksSource
                : new HttpJwksSource(this.http, this.issuer, timeout);
    }

    public static Builder builder() {
        return new Builder();
    }

    public String clientId() {
        return clientId;
    }

    public String issuer() {
        return issuer;
    }

    /**
     * The whole login, in order: exchange the code (with the PKCE verifier
     * the browser SDK handed over) and verify the ID token against the JWKS.
     * Returns a {@link Login}; personal data is NOT fetched here, because the
     * ID token never carries it and not every caller wants it —
     * {@link Login#userinfo()} fetches on first use.
     */
    public Login authenticate(String code, String codeVerifier) {
        return authenticate(code, codeVerifier, null);
    }

    /**
     * As {@link #authenticate(String, String)}, and checks that the ID
     * token's {@code nonce} is the one this login started with. Always pass
     * the nonce when the frontend hands it over: without it the backend
     * cannot tell a substituted ID token from the real one.
     */
    public Login authenticate(String code, String codeVerifier, String nonce) {
        return authenticate(code, codeVerifier, nonce, null);
    }

    /**
     * As {@link #authenticate(String, String, String)}, and — when
     * {@code requiredAcr} is given — refuses a token whose assurance is
     * below it ({@code zoreal.session < zoreal.device < zoreal.live}).
     *
     * <p>REQUESTING an assurance on the wire (the SDK's {@code acr_values})
     * is advisory; the signed {@code acr} claim is the proof, and this
     * parameter is where a relying party that asked for a liveness check
     * verifies it actually happened. An RP that requires {@code zoreal.live}
     * and never passes it here has checked nothing.
     */
    public Login authenticate(String code, String codeVerifier, String nonce, String requiredAcr) {
        TokenResponse tokens = exchange(code, codeVerifier);
        Map<String, Object> claims = verifyIdToken(tokens.idToken(), nonce, requiredAcr);
        return new Login(this, claims, tokens.idToken(), tokens.accessToken(), tokens.scope());
    }

    /**
     * POST {@code {issuer}/token}. The verifier is mandatory: PKCE is
     * required for every ZOREAL client, and the browser SDK that generated
     * it hands it to your frontend precisely so your backend can present it
     * here. Client authentication travels per the configured
     * {@link ClientAuth}.
     */
    public TokenResponse exchange(String code, String codeVerifier) {
        if (isBlank(code)) {
            throw new IllegalArgumentException("code is required");
        }
        if (isBlank(codeVerifier)) {
            throw new IllegalArgumentException("code_verifier is required");
        }

        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", "authorization_code");
        form.put("code", code);
        form.put("code_verifier", codeVerifier);
        // The form always carries client_id, whatever the auth method: the
        // provider matches the code against it.
        form.put("client_id", clientId);

        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(issuer + "/token"))
                .timeout(timeout)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Accept", "application/json")
                .header("User-Agent", USER_AGENT);

        if (auth instanceof ClientAuth.ClientSecretBasic basic) {
            // client_secret_basic: the secret travels as the Basic password,
            // never as a form field.
            request.header("Authorization", basic.authorizationHeader(clientId));
        } else if (auth instanceof ClientAuth.PrivateKeyJwt pkj) {
            form.put("client_assertion_type", ClientAssertion.TYPE);
            form.put("client_assertion", ClientAssertion.build(clientId, issuer, pkj));
        }
        // None and TlsClientAuth add nothing to the form. For tls_client_auth
        // the certificate was already presented in the handshake; the
        // provider currently answers 501 for it, and that surfaces below as
        // the ExchangeException it is.

        HttpResponse<String> response = send(request.POST(HttpRequest.BodyPublishers.ofString(encode(form))).build(),
                "token");
        Map<String, Object> body = parseJson(response.body());
        if (response.statusCode() / 100 != 2) {
            throw new ExchangeException(
                    stringOr(body.get("error"), "server_error"),
                    stringOr(body.get("error_description"), "the provider answered " + response.statusCode()),
                    response.statusCode());
        }
        String idToken = stringOr(body.get("id_token"), null);
        if (isBlank(idToken)) {
            throw new ExchangeException("server_error", "no id_token in the token response", response.statusCode());
        }
        return new TokenResponse(
                idToken,
                stringOr(body.get("access_token"), null),
                stringOr(body.get("token_type"), null),
                body.get("expires_in") instanceof Number n ? n.longValue() : 0L,
                stringOr(body.get("scope"), null),
                body);
    }

    /** As {@link #verifyIdToken(String, String)} with no nonce to hold it to. */
    public Map<String, Object> verifyIdToken(String idToken) {
        return verifyIdToken(idToken, null);
    }

    /**
     * ES256 against the provider's JWKS, plus {@code iss}, {@code aud},
     * {@code exp} and — when the caller passes the nonce the SDK generated —
     * the nonce binding. Returns the claims. There is no RS256 fallback on
     * purpose: ZOREAL signs nothing with RSA, and accepting a second
     * algorithm is how algorithm confusion starts.
     */
    public Map<String, Object> verifyIdToken(String idToken, String nonce) {
        return verifyIdToken(idToken, nonce, null);
    }

    /**
     * As {@link #verifyIdToken(String, String)}, and — when
     * {@code requiredAcr} is given — checks the assurance floor: the token's
     * {@code acr} claim must be a known value of equal or stronger rank
     * ({@code zoreal.session < zoreal.device < zoreal.live}). A token whose
     * {@code acr} is weaker, missing, or outside the vocabulary is refused
     * with a {@link VerificationException}; an unknown REQUIRED value throws
     * {@link ConfigurationException}, because that is a typo in the caller's
     * code, not a bad token.
     */
    public Map<String, Object> verifyIdToken(String idToken, String nonce, String requiredAcr) {
        if (isBlank(idToken)) {
            throw new VerificationException("an ID token is required");
        }
        SignedJWT jwt;
        try {
            jwt = SignedJWT.parse(idToken);
        } catch (ParseException e) {
            throw new VerificationException("the ID token is not a valid compact JWT");
        }

        JWSAlgorithm algorithm = jwt.getHeader().getAlgorithm();
        if (!JWSAlgorithm.ES256.equals(algorithm)) {
            throw new VerificationException(
                    "the ID token is signed with " + algorithm + "; ZOREAL signs ES256 only, so it is refused");
        }

        verifySignature(jwt);

        JWTClaimsSet claims;
        try {
            claims = jwt.getJWTClaimsSet();
        } catch (ParseException e) {
            throw new VerificationException("the ID token payload is not a claims set");
        }

        if (!issuer.equals(claims.getIssuer())) {
            throw new VerificationException("the ID token issuer is not " + issuer);
        }
        List<String> audience = claims.getAudience();
        if (audience == null || !audience.contains(clientId)) {
            throw new VerificationException("the ID token audience is not this client");
        }
        Date expiration = claims.getExpirationTime();
        if (expiration == null || !expiration.after(new Date())) {
            throw new VerificationException("the ID token is expired");
        }
        if (!isBlank(nonce) && !nonce.equals(claims.getClaim("nonce"))) {
            throw new VerificationException("the ID token nonce is not the one this login started with");
        }
        if (!isBlank(requiredAcr)) {
            verifyAcr(claims.getClaim("acr"), requiredAcr);
        }

        return jwt.getPayload().toJSONObject();
    }

    /**
     * Equal or stronger satisfies; anything else — weaker, missing, or a
     * value outside the vocabulary — is refused. An unknown REQUIREMENT is a
     * caller bug and says so plainly rather than failing every login.
     */
    private static void verifyAcr(Object actual, String required) {
        Integer requiredRank = ACR_ORDER.get(required);
        if (requiredRank == null) {
            throw new ConfigurationException("unknown required acr " + required
                    + "; supported: " + String.join(", ", ACR_ORDER.keySet()));
        }
        Integer actualRank = actual instanceof String s ? ACR_ORDER.get(s) : null;
        if (actualRank == null || actualRank < requiredRank) {
            String said = actual instanceof String s ? "\"" + s + "\"" : "nothing";
            throw new VerificationException(
                    "the ID token says acr " + said + ", below the required " + required);
        }
    }

    /**
     * GET {@code {issuer}/userinfo} with the Bearer access token from the
     * exchange. This is the only place personal claims (email, profile.*)
     * are served, and the access token lives ten minutes, so call it as part
     * of handling the login rather than storing the token for later.
     */
    public Map<String, Object> userinfo(String accessToken) {
        if (isBlank(accessToken)) {
            throw new IllegalArgumentException("access_token is required");
        }
        HttpRequest request = HttpRequest.newBuilder(URI.create(issuer + "/userinfo"))
                .timeout(timeout)
                .header("Authorization", "Bearer " + accessToken)
                .header("Accept", "application/json")
                .header("User-Agent", USER_AGENT)
                .GET()
                .build();
        HttpResponse<String> response;
        try {
            response = http.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new UserinfoException("could not reach the userinfo endpoint: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new UserinfoException("the userinfo request was interrupted", e);
        }
        Map<String, Object> body = parseJson(response.body());
        if (response.statusCode() / 100 != 2) {
            throw new UserinfoException(
                    stringOr(body.get("error_description"), "userinfo answered " + response.statusCode()));
        }
        return body;
    }

    private void verifySignature(SignedJWT jwt) {
        String kid = jwt.getHeader().getKeyID();
        List<ECKey> candidates = candidateKeys(jwksSource.get(), kid);
        if (candidates.isEmpty()) {
            // Unknown kid: invalidate and refetch once, which is what a
            // provider key rotation looks like from here. Once, not a loop.
            candidates = candidateKeys(jwksSource.refresh(), kid);
        }
        if (candidates.isEmpty()) {
            throw new VerificationException("the provider JWKS has no ES256 key matching the ID token");
        }
        for (ECKey key : candidates) {
            try {
                if (jwt.verify(new ECDSAVerifier(key.toECPublicKey()))) {
                    return;
                }
            } catch (JOSEException e) {
                // an unusable key is the same as a non-matching one; try the next
            }
        }
        throw new VerificationException("the ID token signature does not verify against the provider JWKS");
    }

    private List<ECKey> candidateKeys(JWKSet set, String kid) {
        if (set == null) {
            return List.of();
        }
        if (kid != null && !kid.isBlank()) {
            JWK match = set.getKeyByKeyId(kid);
            return match instanceof ECKey ec && Curve.P_256.equals(ec.getCurve()) ? List.of(ec) : List.of();
        }
        List<ECKey> keys = new ArrayList<>();
        for (JWK jwk : set.getKeys()) {
            if (KeyType.EC.equals(jwk.getKeyType()) && jwk instanceof ECKey ec && Curve.P_256.equals(ec.getCurve())) {
                keys.add(ec);
            }
        }
        return keys;
    }

    private HttpResponse<String> send(HttpRequest request, String endpoint) {
        try {
            return http.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new ExchangeException("server_error", "could not reach the " + endpoint + " endpoint: " + e.getMessage(), 0);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ExchangeException("server_error", "the " + endpoint + " request was interrupted", 0);
        }
    }

    private static String encode(Map<String, String> form) {
        return form.entrySet().stream()
                .map(entry -> URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8)
                        + "=" + URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8))
                .collect(Collectors.joining("&"));
    }

    private static Map<String, Object> parseJson(String body) {
        if (body == null || body.isBlank()) {
            return Map.of();
        }
        try {
            return JSONObjectUtils.parse(body);
        } catch (ParseException e) {
            return Map.of();
        }
    }

    private static String stringOr(Object value, String fallback) {
        return value instanceof String s && !s.isBlank() ? s : fallback;
    }

    private static String stripTrailingSlash(String value) {
        return value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    /**
     * Builds a {@link ZorealOAuth2Client}. {@code clientId} is required;
     * everything else has a default: issuer {@value #DEFAULT_ISSUER}, auth
     * {@link ClientAuth#none()}, timeout 10 seconds, and a JWKS source that
     * fetches {@code {issuer}/jwks} and caches it for 600 seconds.
     */
    public static final class Builder {

        private String clientId;
        private String issuer = DEFAULT_ISSUER;
        private ClientAuth auth = ClientAuth.none();
        private Duration timeout = Duration.ofSeconds(10);
        private JwksSource jwksSource;

        private Builder() {
        }

        /** The registered client id ({@code ast_...}). Required. */
        public Builder clientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        /**
         * The provider base URL. Must match the {@code iss} inside the
         * tokens exactly — it is compared, not normalized.
         */
        public Builder issuer(String issuer) {
            this.issuer = issuer;
            return this;
        }

        /** One of the four {@link ClientAuth} methods. Default: {@link ClientAuth#none()}. */
        public Builder auth(ClientAuth auth) {
            this.auth = Objects.requireNonNull(auth, "auth must not be null");
            return this;
        }

        /** Connect and per-request timeout. Default 10 seconds. */
        public Builder timeout(Duration timeout) {
            this.timeout = Objects.requireNonNull(timeout, "timeout must not be null");
            return this;
        }

        /** Replace the default HTTP-fetching, 600-second-cached JWKS source. */
        public Builder jwksSource(JwksSource jwksSource) {
            this.jwksSource = jwksSource;
            return this;
        }

        public ZorealOAuth2Client build() {
            return new ZorealOAuth2Client(this);
        }
    }
}

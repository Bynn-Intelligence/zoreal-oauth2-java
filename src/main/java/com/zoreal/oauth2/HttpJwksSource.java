package com.zoreal.oauth2;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;

import com.nimbusds.jose.jwk.JWKSet;

/**
 * The default {@link JwksSource}: GET {@code {issuer}/jwks}, cached for 600
 * seconds. The provider serves its JWKS with a 10-minute public cache;
 * mirroring it here keeps a busy relying party off the endpoint without
 * holding a rotated-out key longer than the provider itself would.
 *
 * <p>Thread-safe: the cache is a volatile pair and {@link #refresh()} is
 * synchronized, so concurrent verifications share one fetch.
 */
final class HttpJwksSource implements JwksSource {

    static final Duration TTL = Duration.ofSeconds(600);

    private final HttpClient http;
    private final URI uri;
    private final Duration timeout;

    private volatile JWKSet cached;
    private volatile Instant freshUntil = Instant.EPOCH;

    HttpJwksSource(HttpClient http, String issuer, Duration timeout) {
        this.http = http;
        this.uri = URI.create(issuer + "/jwks");
        this.timeout = timeout;
    }

    @Override
    public JWKSet get() {
        JWKSet set = cached;
        if (set != null && Instant.now().isBefore(freshUntil)) {
            return set;
        }
        return refresh();
    }

    @Override
    public synchronized JWKSet refresh() {
        HttpRequest request = HttpRequest.newBuilder(uri)
                .timeout(timeout)
                .header("Accept", "application/json")
                .GET()
                .build();
        HttpResponse<String> response;
        try {
            response = http.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new VerificationException("could not fetch the provider JWKS: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new VerificationException("could not fetch the provider JWKS: interrupted", e);
        }
        if (response.statusCode() / 100 != 2) {
            throw new VerificationException("could not fetch the provider JWKS (" + response.statusCode() + ")");
        }
        try {
            JWKSet set = JWKSet.parse(response.body());
            cached = set;
            freshUntil = Instant.now().plus(TTL);
            return set;
        } catch (ParseException e) {
            throw new VerificationException("the provider JWKS did not parse", e);
        }
    }
}

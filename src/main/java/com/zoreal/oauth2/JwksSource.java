package com.zoreal.oauth2;

import com.nimbusds.jose.jwk.JWKSet;

/**
 * Where the provider's signing keys come from. The default implementation
 * fetches {@code {issuer}/jwks} over HTTP and caches it for 600 seconds,
 * mirroring the public cache the provider serves the document with; tests
 * and callers with their own caching inject a different one through
 * {@link ZorealOAuth2Client.Builder#jwksSource(JwksSource)}.
 */
public interface JwksSource {

    /** The current key set, from cache when one is fresh. */
    JWKSet get();

    /**
     * Invalidate and refetch. Called once when an ID token names a
     * {@code kid} the cached set does not have, which is what a provider key
     * rotation looks like from here.
     */
    JWKSet refresh();
}

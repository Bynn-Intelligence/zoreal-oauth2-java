package com.zoreal.oauth2;

import com.nimbusds.jose.jwk.JWKSet;

/**
 * A JwksSource for offline tests: hands back a fixed key set and never
 * touches the network.
 */
final class StaticJwksSource implements JwksSource {

    private final JWKSet set;

    StaticJwksSource(JWKSet set) {
        this.set = set;
    }

    @Override
    public JWKSet get() {
        return set;
    }

    @Override
    public JWKSet refresh() {
        return set;
    }
}

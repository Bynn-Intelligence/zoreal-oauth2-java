package com.zoreal.oauth2;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * What {@code POST {issuer}/token} answered. The access token lives ten
 * minutes; read userinfo while handling the login rather than storing it.
 *
 * @param idToken     the compact ID token JWT, always present on success
 * @param accessToken the Bearer token for userinfo, ten-minute lifetime
 * @param tokenType   {@code "Bearer"}
 * @param expiresIn   access token lifetime in seconds
 * @param scope       the granted scope, which the provider may have narrowed
 * @param raw         the whole response body, for forward compatibility
 */
public record TokenResponse(
        String idToken,
        String accessToken,
        String tokenType,
        long expiresIn,
        String scope,
        Map<String, Object> raw) {

    public TokenResponse {
        raw = raw == null
                ? Map.of()
                : Collections.unmodifiableMap(new LinkedHashMap<>(raw));
    }

    /** The token values stay out of logs. */
    @Override
    public String toString() {
        return "TokenResponse[tokenType=" + tokenType + ", expiresIn=" + expiresIn
                + ", scope=" + scope + ", idToken=REDACTED, accessToken=REDACTED]";
    }
}

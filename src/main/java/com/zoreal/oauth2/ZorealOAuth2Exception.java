package com.zoreal.oauth2;

/**
 * Base class for everything this library throws on its own behalf. All
 * subclasses are unchecked: a failed login is an expected runtime outcome,
 * not a recoverable checked condition at every call site.
 *
 * <p>No exception message in this library ever contains a token, a code, a
 * verifier or a secret.
 */
public class ZorealOAuth2Exception extends RuntimeException {

    public ZorealOAuth2Exception(String message) {
        super(message);
    }

    public ZorealOAuth2Exception(String message, Throwable cause) {
        super(message, cause);
    }
}

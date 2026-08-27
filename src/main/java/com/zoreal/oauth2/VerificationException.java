package com.zoreal.oauth2;

/**
 * The ID token did not verify: bad signature, a non-ES256 algorithm, wrong
 * issuer or audience, expired, a nonce that was not the one this login
 * started with, or a JWKS that could not be fetched.
 */
public class VerificationException extends ZorealOAuth2Exception {

    public VerificationException(String message) {
        super(message);
    }

    public VerificationException(String message, Throwable cause) {
        super(message, cause);
    }
}

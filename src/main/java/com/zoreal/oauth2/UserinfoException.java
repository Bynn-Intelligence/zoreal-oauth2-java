package com.zoreal.oauth2;

/**
 * The userinfo endpoint answered with anything but the claims. Callers that
 * can live without personal data (a returning user matched by sub) may catch
 * this and continue; callers that need the email should not.
 */
public class UserinfoException extends ZorealOAuth2Exception {

    public UserinfoException(String message) {
        super(message);
    }

    public UserinfoException(String message, Throwable cause) {
        super(message, cause);
    }
}

package com.zoreal.oauth2;

/**
 * The provider refused the code exchange. {@link #getOauthError()} is the
 * RFC 6749 error code and {@link #getDescription()} the provider's own
 * reason, verbatim: the provider's words are the only signal that says WHY
 * (a consumed code, a PKCE mismatch, a lapsed sector), and rewriting them
 * hides it. {@link #getStatus()} is the HTTP status, or 0 when the endpoint
 * could not be reached at all.
 */
public class ExchangeException extends ZorealOAuth2Exception {

    private final String oauthError;
    private final String description;
    private final int status;

    public ExchangeException(String oauthError, String description) {
        this(oauthError, description, 0);
    }

    public ExchangeException(String oauthError, String description, int status) {
        super(oauthError + ": " + description);
        this.oauthError = oauthError;
        this.description = description;
        this.status = status;
    }

    /** The RFC 6749 error code, e.g. {@code invalid_grant}. */
    public String getOauthError() {
        return oauthError;
    }

    /** The provider's {@code error_description}, verbatim. */
    public String getDescription() {
        return description;
    }

    /** The HTTP status of the refusal, or 0 when the endpoint was unreachable. */
    public int getStatus() {
        return status;
    }
}

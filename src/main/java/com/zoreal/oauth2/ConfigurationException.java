package com.zoreal.oauth2;

/**
 * The client was built without something it cannot work without: a blank
 * client id, a blank issuer, or private_key_jwt key material that cannot be
 * parsed or cannot sign a supported algorithm.
 */
public class ConfigurationException extends ZorealOAuth2Exception {

    public ConfigurationException(String message) {
        super(message);
    }

    public ConfigurationException(String message, Throwable cause) {
        super(message, cause);
    }
}

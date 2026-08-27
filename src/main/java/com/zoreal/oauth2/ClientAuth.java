package com.zoreal.oauth2;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.ParseException;
import java.util.Base64;
import java.util.Objects;

import javax.net.ssl.SSLContext;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;

/**
 * How the client authenticates at the token endpoint. One of four methods,
 * matching what a ZOREAL client registers as its
 * {@code token_endpoint_auth_method}:
 *
 * <ul>
 *   <li>{@link None} — a public client. No secret, no key; the form carries
 *       {@code client_id} only and PKCE is the only proof. A public client
 *       can only ever have been granted Tier A scopes.</li>
 *   <li>{@link ClientSecretBasic} — confidential. The secret travels as HTTP
 *       Basic (client id as user, secret as password); the form still carries
 *       {@code client_id} because the provider matches the code against
 *       it.</li>
 *   <li>{@link PrivateKeyJwt} — confidential, RFC 7523. The library builds
 *       and signs a short-lived assertion from the caller's private key; the
 *       key itself never travels.</li>
 *   <li>{@link TlsClientAuth} — mutual TLS with the client certificate ZOREAL
 *       issued. Registrable, and the provider currently answers
 *       {@code 501 "tls_client_auth is not implemented at this endpoint
 *       yet"}; the 501 is surfaced as the {@link ExchangeException} it is,
 *       never faked.</li>
 * </ul>
 */
public sealed interface ClientAuth
        permits ClientAuth.None, ClientAuth.ClientSecretBasic, ClientAuth.PrivateKeyJwt, ClientAuth.TlsClientAuth {

    /** A public client: PKCE alone, nothing else to present. */
    static None none() {
        return new None();
    }

    /** A confidential client with a shared secret ({@code zcs_...}). */
    static ClientSecretBasic clientSecretBasic(String clientSecret) {
        return new ClientSecretBasic(clientSecret);
    }

    /**
     * A confidential client with a registered key pair. {@code material} is
     * either a PKCS#8 PEM ({@code -----BEGIN PRIVATE KEY-----}) or a JWK JSON
     * object carrying the private part. P-256 signs ES256 (preferred, it
     * matches the provider's certified-key path); RSA signs RS256.
     */
    static PrivateKeyJwt privateKeyJwt(String material) {
        return privateKeyJwt(material, null);
    }

    /**
     * As {@link #privateKeyJwt(String)}, with an explicit {@code kid} to set
     * on the assertion header so the provider can pick the right registered
     * key. A JWK's own {@code kid} is used when this one is null.
     */
    static PrivateKeyJwt privateKeyJwt(String material, String kid) {
        Objects.requireNonNull(material, "key material is required");
        String trimmed = material.trim();
        if (trimmed.startsWith("{")) {
            return fromJwk(trimmed, kid);
        }
        return new PrivateKeyJwt(parsePkcs8Pem(trimmed), kid);
    }

    /** A confidential client with an already-loaded {@link PrivateKey}. */
    static PrivateKeyJwt privateKeyJwt(PrivateKey key, String kid) {
        return new PrivateKeyJwt(key, kid);
    }

    /**
     * Mutual TLS. The {@link SSLContext} must carry the client certificate
     * and its private key (a {@code KeyManager} over your keystore); it is
     * installed on the underlying {@link java.net.http.HttpClient}, so the
     * certificate is presented on every connection this client opens.
     */
    static TlsClientAuth tlsClientAuth(SSLContext sslContext) {
        return new TlsClientAuth(sslContext);
    }

    /** Public client: the token request carries {@code client_id} and PKCE only. */
    record None() implements ClientAuth {
    }

    /** Confidential client, shared secret over HTTP Basic. */
    record ClientSecretBasic(String clientSecret) implements ClientAuth {

        public ClientSecretBasic {
            if (clientSecret == null || clientSecret.isBlank()) {
                throw new ConfigurationException("client_secret_basic needs a client secret");
            }
        }

        /** The Basic credential, built here so the secret never sits in a form field. */
        String authorizationHeader(String clientId) {
            String pair = clientId + ":" + clientSecret;
            return "Basic " + Base64.getEncoder().encodeToString(pair.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        }

        /** The secret stays out of logs. */
        @Override
        public String toString() {
            return "ClientSecretBasic[clientSecret=REDACTED]";
        }
    }

    /** Confidential client, RFC 7523 signed assertion. */
    record PrivateKeyJwt(PrivateKey key, String kid) implements ClientAuth {

        public PrivateKeyJwt {
            Objects.requireNonNull(key, "private_key_jwt needs a private key");
            String algorithm = key.getAlgorithm();
            if (!"EC".equals(algorithm) && !"RSA".equals(algorithm)) {
                throw new ConfigurationException(
                        "private_key_jwt signs ES256 with a P-256 key or RS256 with an RSA key; got a "
                                + algorithm + " key");
            }
        }

        /** The key stays out of logs. */
        @Override
        public String toString() {
            return "PrivateKeyJwt[key=REDACTED, kid=" + kid + "]";
        }
    }

    /** Mutual TLS with the issued client certificate. */
    record TlsClientAuth(SSLContext sslContext) implements ClientAuth {

        public TlsClientAuth {
            Objects.requireNonNull(sslContext, "tls_client_auth needs an SSLContext carrying the client certificate");
        }
    }

    private static PrivateKeyJwt fromJwk(String json, String kid) {
        try {
            JWK jwk = JWK.parse(json);
            if (!jwk.isPrivate()) {
                throw new ConfigurationException("the JWK does not carry a private key");
            }
            String effectiveKid = kid != null ? kid : jwk.getKeyID();
            if (jwk instanceof ECKey ec) {
                return new PrivateKeyJwt(ec.toECPrivateKey(), effectiveKid);
            }
            if (jwk instanceof RSAKey rsa) {
                return new PrivateKeyJwt(rsa.toRSAPrivateKey(), effectiveKid);
            }
            throw new ConfigurationException(
                    "private_key_jwt signs ES256 with a P-256 key or RS256 with an RSA key; got a "
                            + jwk.getKeyType() + " JWK");
        } catch (ParseException | JOSEException e) {
            throw new ConfigurationException("the JWK could not be parsed as a private key", e);
        }
    }

    private static PrivateKey parsePkcs8Pem(String pem) {
        if (pem.contains("-----BEGIN EC PRIVATE KEY-----") || pem.contains("-----BEGIN RSA PRIVATE KEY-----")) {
            throw new ConfigurationException(
                    "the key is in the traditional OpenSSL format; convert it to PKCS#8 with "
                            + "`openssl pkcs8 -topk8 -nocrypt -in key.pem`");
        }
        String base64 = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] der;
        try {
            der = Base64.getDecoder().decode(base64);
        } catch (IllegalArgumentException e) {
            throw new ConfigurationException("the PEM body is not valid base64", e);
        }
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
        for (String algorithm : new String[] {"EC", "RSA"}) {
            try {
                return KeyFactory.getInstance(algorithm).generatePrivate(spec);
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                // try the next algorithm
            }
        }
        throw new ConfigurationException(
                "the PEM did not parse as an EC or RSA PKCS#8 private key (-----BEGIN PRIVATE KEY-----)");
    }
}

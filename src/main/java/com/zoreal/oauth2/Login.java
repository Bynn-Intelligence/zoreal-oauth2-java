package com.zoreal.oauth2;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * One verified login. The ID token claims are already checked when this
 * exists; userinfo is fetched on first use, because the ID token never
 * carries personal data and not every login needs any.
 *
 * <p>Thread-safe: the claims are immutable and the userinfo fetch is
 * memoized under a lock, so concurrent readers share one request.
 */
public final class Login {

    private final ZorealOAuth2Client client;
    private final Map<String, Object> claims;
    private final String idToken;
    private final String accessToken;
    private final String scope;

    private final Object userinfoLock = new Object();
    private volatile Map<String, Object> userinfoCache;

    Login(ZorealOAuth2Client client, Map<String, Object> claims, String idToken,
          String accessToken, String scope) {
        this.client = client;
        this.claims = Collections.unmodifiableMap(new LinkedHashMap<>(claims));
        this.idToken = idToken;
        this.accessToken = accessToken;
        this.scope = scope;
    }

    /** The verified ID token claims. */
    public Map<String, Object> claims() {
        return claims;
    }

    /** The raw compact JWT the claims came from. */
    public String idToken() {
        return idToken;
    }

    /** From the token response. The access token lives ten minutes. */
    public Optional<String> accessToken() {
        return Optional.ofNullable(accessToken);
    }

    /** The granted scope, which the provider may have narrowed. */
    public Optional<String> scope() {
        return Optional.ofNullable(scope);
    }

    /**
     * The pairwise subject: stable for your verified domain, meaningless to
     * anyone else. This is the value to key accounts on — and it is derived
     * from YOUR registered sector, so changing your asset's domain rotates
     * every sub you have stored.
     */
    public String sub() {
        return (String) claims.get("sub");
    }

    /**
     * How the login was authenticated: {@code zoreal.live},
     * {@code zoreal.device} or {@code zoreal.session}. Describes what
     * happened, never what was requested.
     */
    public String acr() {
        return (String) claims.get("acr");
    }

    /**
     * A fresh liveness capture backed this login. The convenience spelling
     * of {@code acr().equals("zoreal.live")}; for enforcement, pass a
     * required acr to {@code authenticate} and let verification refuse the
     * token instead of checking after.
     */
    public boolean live() {
        return "zoreal.live".equals(acr());
    }

    /**
     * Equal or stronger satisfies, on the client's ordering
     * ({@code zoreal.session < zoreal.device < zoreal.live}). Unknown
     * values satisfy nothing.
     */
    public boolean satisfiesAcr(String required) {
        Integer actual = ZorealOAuth2Client.ACR_ORDER.get(acr());
        Integer wanted = ZorealOAuth2Client.ACR_ORDER.get(required);
        return actual != null && wanted != null && actual >= wanted;
    }

    /** The authentication methods, e.g. {@code ["hwk", "face", "user"]}. */
    @SuppressWarnings("unchecked")
    public List<String> amr() {
        Object value = claims.get("amr");
        return value instanceof List<?> ? (List<String>) value : List.of();
    }

    /**
     * The assurance block: uniqueness basis, verification month, chip
     * liveness, trust tier, key protection.
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> assurance() {
        Object value = claims.get("zoreal");
        return value instanceof Map<?, ?> ? (Map<String, Object>) value : Map.of();
    }

    /**
     * zoreal.age scope: the registered thresholds arrive as booleans
     * ({@code age_over_18} and so on), never an age. Empty when the
     * threshold was not registered for this client.
     */
    public Optional<Boolean> ageOver(int threshold) {
        Object value = claims.get("age_over_" + threshold);
        return value instanceof Boolean b ? Optional.of(b) : Optional.empty();
    }

    /** zoreal.nationality scope: ISO 3166-1 alpha-3, read from the chip. */
    public Optional<String> nationality() {
        return claimString(claims, "nationality");
    }

    /**
     * The Tier B claims, from {@code /userinfo}, fetched once and memoized.
     * Throws {@link UserinfoException} when the endpoint refuses — catch it
     * if your flow can continue without personal data, as a returning user
     * matched on {@link #sub()} can. Returns an empty map when the exchange
     * carried no access token.
     */
    public Map<String, Object> userinfo() {
        Map<String, Object> cached = userinfoCache;
        if (cached != null) {
            return cached;
        }
        synchronized (userinfoLock) {
            if (userinfoCache == null) {
                userinfoCache = accessToken == null || accessToken.isBlank()
                        ? Map.of()
                        : Collections.unmodifiableMap(new LinkedHashMap<>(client.userinfo(accessToken)));
            }
            return userinfoCache;
        }
    }

    /** email scope: the address the holder verified with ZOREAL. */
    public Optional<String> email() {
        return claimString(userinfo(), "email");
    }

    /** email scope: true only when the provider says so. */
    public boolean emailVerified() {
        return Boolean.TRUE.equals(userinfo().get("email_verified"));
    }

    /** profile.name scope. */
    public Optional<String> name() {
        return claimString(userinfo(), "name");
    }

    /** profile.name scope. */
    public Optional<String> givenName() {
        return claimString(userinfo(), "given_name");
    }

    /** profile.name scope. */
    public Optional<String> familyName() {
        return claimString(userinfo(), "family_name");
    }

    /** profile.birthdate scope: ISO 8601, e.g. {@code 1990-04-21}. */
    public Optional<String> birthdate() {
        return claimString(userinfo(), "birthdate");
    }

    /** profile.document scope. */
    public Optional<String> documentType() {
        return claimString(userinfo(), "document_type");
    }

    /** profile.document scope. */
    public Optional<String> documentNumber() {
        return claimString(userinfo(), "document_number");
    }

    /** profile.document scope: ISO 3166-1 alpha-3. */
    public Optional<String> issuingCountry() {
        return claimString(userinfo(), "issuing_country");
    }

    /** profile.document scope: ISO 8601. */
    public Optional<String> documentExpiresOn() {
        return claimString(userinfo(), "document_expires_on");
    }

    /**
     * profile.portrait scope. The scope is registrable but the provider does
     * not serve the portrait claim yet, so this stays empty for now; when
     * the provider ships it, this accessor starts returning it with no
     * library change.
     */
    public Optional<String> portrait() {
        return claimString(userinfo(), "portrait");
    }

    /** The tokens stay out of logs. */
    @Override
    public String toString() {
        return "Login[sub=" + sub() + ", acr=" + acr() + ", scope=" + scope + "]";
    }

    private static Optional<String> claimString(Map<String, Object> source, String key) {
        Object value = source.get(key);
        return value instanceof String s ? Optional.of(s) : Optional.empty();
    }
}

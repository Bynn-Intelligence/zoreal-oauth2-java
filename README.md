# zoreal-oauth2 for the JVM

[![Maven Central](https://img.shields.io/maven-central/v/com.zoreal/oauth2)](https://central.sonatype.com/artifact/com.zoreal/oauth2) [![CI](https://img.shields.io/github/actions/workflow/status/Bynn-Intelligence/zoreal-oauth2-java/ci.yml?branch=main&label=CI)](https://github.com/Bynn-Intelligence/zoreal-oauth2-java/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

Login with ZOREAL for JVM backends: the relying-party half of the flow that
[`@zoreal/oauth2-react`](https://github.com/Bynn-Intelligence/zoreal-oauth2-react)
starts in the browser.

The browser SDK runs the pairing (QR or app link), and hands your frontend an
authorization `code` plus the `code_verifier` and `nonce` it generated. Your
frontend posts all three to your backend, and this library does the rest: the
code exchange with your client authentication, ES256 verification of the ID
token against the provider's JWKS, and the `/userinfo` read for personal
claims.

```
com.zoreal:oauth2 (this library)   your backend: exchange, verify, userinfo
@zoreal/oauth2-react               your frontend: the button, the QR, the polling
```

## Install

```xml
<dependency>
  <groupId>com.zoreal</groupId>
  <artifactId>oauth2</artifactId>
  <version>0.1.2</version>
</dependency>
```

The version above tracks this commit; the newest is always on the
[releases page](https://github.com/Bynn-Intelligence/zoreal-oauth2-java/releases)
and on [Maven Central](https://central.sonatype.com/artifact/com.zoreal/oauth2).

Java 17 or newer. One dependency: `com.nimbusds:nimbus-jose-jwt`.

## Getting your credentials

Everything the builder needs comes from a ZOREAL **asset**.

1. Create an account at **https://zoreal.com** and open **Assets**.
2. **Create an asset** — a *website* (a domain you own) or an *app bundle* (a
   reverse-DNS bundle id). An asset is the thing users log in to; its token is
   your `client_id` and it looks like `ast_...`.
3. On the asset, open the **OAuth2** tab and set:
   - the **redirect URIs** and **JavaScript origins** your app uses (requests
     from anything not registered are rejected — this is the core control),
   - the **scopes** the client is allowed to request (see the catalogue below),
   - your **client authentication**: generate a **client secret**
     (`client_secret_basic`), or register a **JWKS** for `private_key_jwt`. A
     public client authenticates with PKCE alone and no secret.
4. A website asset must **verify its domain** (a DNS or meta-tag proof, shown in
   the dashboard) before it can request personal-data scopes or sign users in;
   the verified domain is what your users' `sub` is pairwise against.

The `client_id` is public (it ships in your frontend). The client secret is not
— keep it in your server's secret store, never in the browser.

### There is no test-identity sandbox — and that is deliberate

ZOREAL **never issues fake or sandbox humans**: a pool of test identities would
be a fraud vector against the exact thing the product proves. So you always
authenticate **real** ZOREAL IDs.

To develop and test, **create a free ZOREAL ID for yourself** (enrol in the
ZOREAL ID app) and sign in with it. Mark your asset's environment **sandbox** in
the dashboard while building — a sandbox asset may register `http://localhost`
origins and redirect URIs that a production asset may not — and flip it to
production when you ship. The identities are real either way; only the allowed
origins differ.

## Quick start

Build one client at boot and share it; it is immutable and thread-safe.

```java
ZorealOAuth2Client zoreal = ZorealOAuth2Client.builder()
        .clientId(System.getenv("ZOREAL_CLIENT_ID"))                      // ast_...
        .auth(ClientAuth.clientSecretBasic(System.getenv("ZOREAL_CLIENT_SECRET")))
        .issuer(System.getenv().getOrDefault("ZOREAL_ISSUER", "https://id.zoreal.com"))
        .build();
```

The endpoint your frontend posts to:

```java
Login login = zoreal.authenticate(
        body.code(),
        body.codeVerifier(),   // PKCE is mandatory; the SDK hands it over
        body.nonce());         // binds the ID token to this login

login.sub();            // "TC5X-JN7G-YTSE-6E63" — pairwise, stable for YOUR domain
login.acr();            // "zoreal.live" | "zoreal.device" | "zoreal.session"
login.assurance();      // uniqueness basis, verification month, chip liveness, trust tier
login.email();          // Optional, from /userinfo, when your client has the email scope
login.emailVerified();
login.name();           // Optional, from /userinfo, profile.name scope
```

Account matching, the shape that works:

```java
User user = users.findByProviderUid("zoreal", login.sub());
if (user == null) {
    if (login.emailVerified()) {
        user = users.findByEmail(login.email().orElse(null));  // claim, don't collide
    }
    if (user == null) {
        user = users.create(login.email().orElse(null));
    }
    user.linkProvider("zoreal", login.sub());
}
```

## Assurance levels — `acr`, and requiring a liveness check

### What `acr` is

`acr` is an OpenID Connect standard claim — *Authentication Context Class
Reference*. It is a single string in the ID token that says **how strongly this
particular login was authenticated**. Every ZOREAL login carries one, and it is
the difference between "someone who once enrolled this identity is behind this
request" and "a live human, verified to be the right one, is behind this request
right now".

It answers a question the `sub` cannot. `sub` tells you *who* (a stable, pairwise
identifier for this person at your site). `acr` tells you *how sure ZOREAL is that
the person is really there for this login*. A stolen, unlocked phone can still
produce a `sub`; it cannot produce a fresh `zoreal.live`.

### The three levels

Ordered weakest to strongest. Each is what actually happened, never what was
requested — a login that could only reach a weaker level says so honestly rather
than claiming the level you asked for.

| `acr` | What the holder did | `amr` | What it proves | What it does **not** prove |
|---|---|---|---|---|
| `zoreal.session` | Nothing — a returning holder at a site they have used before, resumed silently from an existing ZOREAL session, no phone interaction | `[]` | Continuity: the same browser/session ZOREAL already knew | That the holder is present, or even awake |
| `zoreal.device` | Approved the login on their enrolled phone: a signature from a key in the phone's secure element, released by a local biometric or passcode unlock | `["hwk","user"]` | Possession of the enrolled device **and** a local unlock on it | That a live face was captured for *this* login — an unlocked phone in the wrong hands still signs |
| `zoreal.live` | All of the above **plus** a fresh face capture this login: a flash-plus-zoom video scored for presentation attacks and screen replay (moire), matched 1:1 against the government document read at enrolment | `["hwk","face","user"]` | A live, real, unique human, verified to be the enrolled person, **at the moment of this login** | — (this is the strongest level) |

`amr` (*Authentication Methods References*) is the companion claim listing the
factors used: `hwk` a hardware key, `user` a user-presence/unlock gesture, `face`
a face biometric. `zoreal.live` is exactly `zoreal.device` with `face` added,
because a live login is a device approval with a capture on top. Read it as a
`List<String>` from `login.amr()`.

The **default is `zoreal.device`**, never `zoreal.session`: a login that asks for
nothing still requires the enrolled phone and a local unlock. Silence has to be
explicitly asked for (`prompt=none`), and it succeeds only for a returning holder
at a site whose consent they have already given.

### When to require which

- **`zoreal.session`** — you never *require* this; it is what a returning holder
  gets for a low-stakes convenience re-auth when they ask for the silent path.
- **`zoreal.device`** (the default) — a forum, a community, a normal account
  login. Possession of the enrolled phone plus a local unlock is a high bar
  already; most sites want exactly this and should pass no required acr at all
  (the three-argument `authenticate`).
- **`zoreal.live`** — a bank onboarding, a high-value transaction, an age-gated
  purchase, a first login, a "confirm it is really you" step before a sensitive
  action. Anywhere a *fresh, unforgeable proof of the live, right human* is worth
  the few seconds a face capture costs.

### Requesting versus verifying — the one rule that matters

Requesting a level and verifying it are **two separate steps, and only the second
is security**:

1. **Request** it on the wire, in the frontend, with the SDK's
   `acr_values: 'zoreal.live'`. This is what makes the holder's ZOREAL ID app run
   the face capture before it will approve. It is **advisory** — it shapes what
   the holder is asked to do, nothing more. A browser is attacker-controlled; a
   value that only travels through it proves nothing.
2. **Verify** it here, at token exchange, by passing the required-acr argument to
   `authenticate` (the fourth parameter). The signed `acr` claim in the ID token
   — minted by ZOREAL, not by the browser — is the proof.

```java
Login login = zoreal.authenticate(
        body.code(), body.codeVerifier(), body.nonce(),
        "zoreal.live");   // throws VerificationException unless the signed token says so

login.acr();                            // "zoreal.live" — what actually happened
login.live();                           // convenience: acr().equals("zoreal.live")
login.satisfiesAcr("zoreal.device");    // true (live is stronger than device)
```

The same fourth argument exists on `verifyIdToken(idToken, nonce, requiredAcr)`
when you verify a token you already hold.

**An RP that requests `zoreal.live` on the wire but never passes the required-acr
argument here has checked nothing** — it has only asked the holder nicely and then
trusted a value it never validated.

### How the check behaves

Verification satisfies **upward**: `zoreal.session < zoreal.device <
zoreal.live` (the ordering the library exposes as
`ZorealOAuth2Client.ACR_ORDER`), so a requirement of `zoreal.device` accepts a
`zoreal.live` token — the holder gave you *more* assurance than you demanded. A
token whose `acr` is below the requirement, missing entirely, or outside the
vocabulary is refused with `VerificationException`. An unknown *required* value —
a typo like `"zoreal.liveness"` — throws `ConfigurationException` instead,
because that is a bug in your code, not a bad token, and failing every login
silently is worse than saying so.

If you prefer to branch rather than throw, use the three-argument `authenticate`
and inspect the result with `satisfiesAcr`:

```java
Login login = zoreal.authenticate(body.code(), body.codeVerifier(), body.nonce());
if (!login.satisfiesAcr("zoreal.live")) {
    // step the user up, or refuse the sensitive action
}
```

### `acr` versus the assurance block

Do not confuse `acr` with `login.assurance()`. `acr` grades *this login event*.
The **assurance block** (`login.assurance()`, a `Map` of the ZOREAL assurance
claims) describes the *identity behind it* — how the person was verified at
enrolment: the uniqueness basis, the verification month, whether chip liveness
was proven, the trust tier, and how the device's key is protected. One is about
now; the other is about who they are. A high-value flow usually wants both:
`"zoreal.live"` for presence, and the assurance block for the strength of the
underlying identity proofing. Its schema is the [assurance block](#the-assurance-block)
section below.

## What each call does

| Call | What happens |
|---|---|
| `authenticate(code, codeVerifier, nonce)` | `exchange` + `verifyIdToken`, returns a `Login` |
| `exchange(code, codeVerifier)` | `POST {issuer}/token` with the configured client authentication |
| `verifyIdToken(jwt, nonce)` | ES256 against `{issuer}/jwks`, checks `iss`, `aud`, `exp`, and `nonce` when given |
| `userinfo(accessToken)` | `GET {issuer}/userinfo` with the Bearer token |
| `Login#userinfo()` | the above, once, memoized; an empty map when there is no access token |

`Login` exposes every claim the scope catalogue can grant: `sub()`, `acr()`,
`amr()`, `assurance()`, `ageOver(int)`, `nationality()` from the ID token;
`email()`, `emailVerified()`, `name()`, `givenName()`, `familyName()`,
`birthdate()`, `documentType()`, `documentNumber()`, `issuingCountry()`,
`documentExpiresOn()` and `portrait()` from `/userinfo`. Every `/userinfo`
accessor returns an `Optional` (`portrait()` is registrable but not served by the
provider yet, and stays empty until it is).

## Client authentication

Four methods, matching what your client registers as its
`token_endpoint_auth_method`. Pick the one from your asset's OAuth2 tab.

```java
// Public client: PKCE is the only proof, and only Tier A scopes were ever possible.
ClientAuth.none()

// Confidential client, shared secret. The secret travels as HTTP Basic,
// never as a form field.
ClientAuth.clientSecretBasic("zcs_...")

// Confidential client, RFC 7523. The library builds and signs a fresh
// 60-second assertion per exchange (iss = sub = client id, aud =
// {issuer}/token, single-use jti); the key itself never travels. PKCS#8 PEM
// (-----BEGIN PRIVATE KEY-----) or a JWK JSON string; P-256 signs ES256
// (preferred), RSA signs RS256.
ClientAuth.privateKeyJwt(Files.readString(Path.of("zoreal-key.pem")), "my-kid")

// Mutual TLS with the client certificate ZOREAL issued. The SSLContext
// carries the certificate and key; it is installed on the underlying
// java.net.http.HttpClient so the certificate is presented in the handshake.
ClientAuth.tlsClientAuth(sslContext)
```

`tls_client_auth` is registrable, but the provider does not accept it at the
token endpoint yet: today the exchange answers
`501 "tls_client_auth is not implemented at this endpoint yet"`, and this
library surfaces that as the `ExchangeException` it is rather than pretending
otherwise. Use `private_key_jwt` or `client_secret_basic` until it lands.

## Scopes and claims

Scopes are requested in the **frontend** (the SDK's `scope` string, always
starting with `openid`), consented to by the holder, and pre-authorized on your
asset. What each grants and where it is delivered:

| Scope | Claims | Delivered in | Tier | Requires |
|---|---|---|---|---|
| `openid` | `sub`, `iss`, `aud`, `exp`, `iat`, `nonce`, `auth_time`, `acr`, `amr`, and the assurance block | ID token | A | any client |
| `zoreal.age` | `age_over_13/16/18/21/65` booleans — only the thresholds you registered, never an age or birthdate | ID token | A | any client |
| `zoreal.nationality` | `nationality` (ISO 3166-1 alpha-3) | ID token | A | any client |
| `email` | `email`, `email_verified` | `/userinfo` | B | confidential client + verified domain |
| `profile.name` | `name`, `given_name`, `family_name` | `/userinfo` | B | confidential client + verified domain |
| `profile.birthdate` | `birthdate` (full ISO 8601 date) | `/userinfo` | B | confidential client + verified domain |
| `profile.document` | `document_type`, `document_number`, `issuing_country`, `document_expires_on` | `/userinfo` | B | confidential client + verified domain |
| `profile.portrait` | `portrait` (the chip's facial image; GDPR Article 9 data) | `/userinfo` | C | confidential client + verified domain — *registrable but not served yet* |

- **Tier A** rides in the ID token and is available to every client, so the
  no-backend browser button can use it. **Tier B and C** are personal data,
  served only from `/userinfo` to a confidential client on a domain you have
  verified, and never placed in a browser token.
- **Age thresholds are a fixed set** — 13, 16, 18, 21, 65 — that you register on
  the asset. `login.ageOver(n)` returns an empty `Optional` for a threshold you
  did not register (no claim was minted), which is different from
  `Optional.of(false)`.

## Error reference

`exchange` / `authenticate` throw `ExchangeException`, which carries the
provider's own error code (`getOauthError()`) and reason (`getDescription()`)
verbatim, plus the HTTP status (`getStatus()`, or 0 when the endpoint could not
be reached). What you will actually see:

| `getOauthError()` | Cause | Retryable? |
|---|---|---|
| `invalid_grant` | The code is spent — unknown, expired (60s), already used, PKCE mismatch, or the asset's domain verification lapsed mid-flow | No. Start a **new** login; the code cannot be reused |
| `invalid_request` | Client authentication failed — wrong secret, a bad `private_key_jwt` assertion, or `tls_client_auth` (not accepted at `/token` yet) | No. Fix your client configuration |
| `unsupported_grant_type` | Something other than `authorization_code` reached `/token` | No. A bug |

Errors that surface in the **frontend** instead, before your backend is
involved (from the SDK's `onError` / `onNonOAuthError`), so handle them there:

| Where | Code | Meaning |
|---|---|---|
| `/pair` | `invalid_scope` | A scope not on the asset's allowed list, or a Tier B scope from a public client |
| `/pair` | `invalid_request` | Missing PKCE/nonce, an unverified sector, an unregistered `redirect_uri`, or an unknown `acr_values` |
| `/pair` | `login_required` | `prompt=none` with no silent session to resume — the expected quiet outcome, not a failure |
| pairing | `request_denied` | The holder declined in their ZOREAL ID app — **not an error to alarm on**; offer to try again |
| pairing | `request_expired` | The pairing window elapsed, or a required liveness the device could not meet — offer to try again |

The library's own exceptions — all unchecked, all extending
`ZorealOAuth2Exception`, and none of them ever containing a token value:

| Exception | What it means |
|---|---|
| `ConfigurationException` | You built the client wrong (a blank client id or issuer, unparseable `private_key_jwt` material), or asked to verify an acr outside the vocabulary — a bug in your code, not a bad token |
| `ExchangeException` | The provider refused the code exchange; carries `getOauthError()`, `getDescription()` and `getStatus()` (see the tables above) |
| `VerificationException` | The ID token did not verify: signature, a non-ES256 algorithm, `iss`, `aud`, `exp`, `nonce`, or the acr floor |
| `UserinfoException` | The `/userinfo` call failed. A returning user matched on `sub` can survive a caught `UserinfoException`; a signup that needs the email cannot |

## The assurance block

`login.assurance()` is the ID token's `zoreal` claim — a `Map` describing the
strength of the *identity* behind this login (distinct from `acr`, which grades
the *login event*). Its keys and their value sets:

| Key | Values | Meaning |
|---|---|---|
| `uniqueness` | `personal_number` \| `document` \| `none` | The anchor the holder is deduplicated on. `personal_number` (a national number from the chip) is strongest; `none` means no reliable anchor |
| `verified_on` | `"YYYY-MM"` | The month the underlying document was verified. Quantised to a month on purpose — a day-precision date is a cross-site correlator |
| `chip_liveness_proven` | `true` \| `false` | Whether the passport chip's active-authentication challenge was proven (a genuine chip, not a clone) |
| `trust_tier` | `high` \| `standard` | `high` when `chip_liveness_proven`, else `standard` |
| `key_protection` | `secure_enclave` \| `strongbox` \| `tee` \| `software` | How the holder's device key is protected. `software` means no hardware attestation |

A high-value flow usually pairs `"zoreal.live"` (fresh presence) with a check on
the assurance block (identity strength) — e.g. requiring
`"personal_number".equals(login.assurance().get("uniqueness"))` and
`"high".equals(login.assurance().get("trust_tier"))`.

## A complete example

A Spring `@RestController`, end to end — the shape a real integration takes. The
`ZorealOAuth2Client` is the singleton built at boot and injected here.

```java
// The request body your frontend posts.
public record ZorealLoginRequest(String code, String codeVerifier, String nonce) {}

@RestController
public class SessionController {

    private static final Logger log = LoggerFactory.getLogger(SessionController.class);

    private final ZorealOAuth2Client zoreal;
    private final UserRepository users;

    public SessionController(ZorealOAuth2Client zoreal, UserRepository users) {
        this.zoreal = zoreal;
        this.users = users;
    }

    // Your frontend's ZorealLogin onSuccess posts { code, codeVerifier, nonce }
    // here over your own TLS. Protect this endpoint with your normal CSRF /
    // same-origin controls, exactly as you would any login endpoint — the ZOREAL
    // nonce protects the token, not your route.
    @PostMapping("/auth/zoreal")
    public ResponseEntity<Map<String, Object>> zoreal(
            @RequestBody ZorealLoginRequest body, HttpServletRequest request) {
        try {
            Login login = zoreal.authenticate(
                    body.code(), body.codeVerifier(), body.nonce());
            // For a step-up / high-value login, pass a required acr as the fourth
            // argument: zoreal.authenticate(..., "zoreal.live").

            User user = users.findByProviderUid("zoreal", login.sub());
            if (user == null) {
                // Claim an existing account that owns this verified email rather
                // than colliding on the unique index; otherwise create one.
                if (login.emailVerified()) {
                    user = users.findByEmail(login.email().orElse(null));
                }
                if (user == null) {
                    user = users.create(login.email().orElse(null), login.name().orElse(null));
                }
                user.linkProvider("zoreal", login.sub());
            }

            request.changeSessionId();                          // fixation defence
            request.getSession().setAttribute("userId", user.id());
            return ResponseEntity.ok(Map.of("ok", true));

        } catch (ExchangeException | VerificationException e) {
            // A spent code or a token that did not verify: the login must be restarted.
            log.warn("ZOREAL login failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "sign_in_failed"));
        } catch (UserinfoException e) {
            // Personal data was unreachable. Fine for a returning user matched on
            // sub; fatal for a signup that needs the email.
            log.warn("ZOREAL userinfo failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "sign_in_failed"));
        }
    }
}
```

## Things worth knowing before you integrate

- **The ID token never carries personal data.** `sub`, timing, `acr`/`amr`,
  the assurance block, and — if registered — `age_over_*` booleans and
  `nationality`. Email, names, birthdate and document fields come only from
  `/userinfo`, which is why `authenticate` alone is not enough for a signup.
- **The access token lives 10 minutes.** Read `/userinfo` while handling the
  login; do not store the token for later.
- **`sub` is pairwise per verified domain.** It is the right account key and
  it is derived from your registered sector: changing your asset's domain
  rotates every `sub` you have stored. Plan domain changes as a migration.
- **ES256 only.** The provider signs with nothing else, and this library
  refuses other algorithms rather than negotiating.
- **Always pass the nonce through, and protect your own endpoint too.** The SDK
  generates the nonce and gives it to your frontend in `onSuccess`; passing it
  here lets the library confirm the ID token was minted for *this* login rather
  than substituted. Two things it does **not** do: it is not your endpoint's
  CSRF token (protect your `/auth/zoreal` route with your framework's normal
  CSRF / same-origin defence), and PKCE — not the nonce — is what proves whoever
  exchanges the code is whoever started the flow.
- **Email is a deliberate choice.** It is a Tier B scope precisely because a
  shared email defeats the unlinkability the pairwise `sub` provides. Request
  it because you need it, not because the checkbox is familiar.
- **`profile.portrait` is registrable but not served yet.** The scope can be
  granted and `Login#portrait()` exists, but the provider does not deliver the
  claim today; the accessor stays empty until it does, and starts returning it
  with no library change once it lands.
- **The `issuer` must match the token's `iss` exactly** — it is compared, not
  normalized. Production is `https://id.zoreal.com`; override `issuer(...)` only
  when pointing at a non-production provider you were given.

## The ZOREAL OAuth2 library family

| Repository | Package | Role |
|---|---|---|
| zoreal-oauth2-react | @zoreal/oauth2-react (npm) | React frontend: the button, the QR, the polling |
| zoreal-oauth2-js | @zoreal/oauth2-js (npm) | Framework-free browser core |
| zoreal-oauth2-react-native | @zoreal/oauth2-react-native (npm) | React Native frontend |
| zoreal-oauth2-node | @zoreal/oauth2-node (npm) | Node.js backend |
| zoreal-oauth2-ruby | zoreal-oauth2 (RubyGems) | Ruby backend |
| zoreal-oauth2-python | zoreal-oauth2 (PyPI) | Python backend |
| zoreal-oauth2-php | zoreal/oauth2 (Packagist) | PHP backend |
| zoreal-oauth2-go | github.com/Bynn-Intelligence/zoreal-oauth2-go | Go backend |
| zoreal-oauth2-java | com.zoreal:oauth2 (Maven Central) | JVM backend |
| zoreal-oauth2-dotnet | Zoreal.OAuth2 (NuGet) | .NET backend |

## License

MIT.

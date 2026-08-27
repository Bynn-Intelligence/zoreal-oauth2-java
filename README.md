# zoreal-oauth2 for the JVM

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
underlying identity proofing.

## What each call does

| Call | What happens |
|---|---|
| `authenticate(code, codeVerifier, nonce)` | `exchange` + `verifyIdToken`, returns a `Login` |
| `exchange(code, codeVerifier)` | `POST {issuer}/token` with the configured client authentication |
| `verifyIdToken(jwt, nonce)` | ES256 against `{issuer}/jwks`, checks `iss`, `aud`, `exp`, and `nonce` when given |
| `userinfo(accessToken)` | `GET {issuer}/userinfo` with the Bearer token |
| `Login#userinfo()` | the above, once, memoized; an empty map when there is no access token |

Errors: `ConfigurationException`, `ExchangeException` (carries the provider's
OAuth error code, reason and HTTP status, verbatim), `VerificationException`,
`UserinfoException` — all unchecked, all extending `ZorealOAuth2Exception`,
and none of them ever contains a token value. A returning user matched on
`sub` can survive a caught `UserinfoException`; a signup that needs the email
cannot.

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
- **Always pass the nonce through.** The SDK generates it and gives it to your
  frontend in `onSuccess`; without it your backend cannot tell a substituted
  ID token from the real one.
- **Email is a deliberate choice.** It is a Tier B scope precisely because a
  shared email defeats the unlinkability the pairwise `sub` provides. Request
  it because you need it, not because the checkbox is familiar.
- **Sandbox clients accept localhost origins; production clients do not.**
  Registration lives in the ZOREAL dashboard on the asset's OAuth2 tab; Tier B
  scopes (email, profile.\*) need a confidential client on a verified domain.
- **`profile.portrait` is registrable but not served yet.** The scope can be
  granted and `Login#portrait()` exists, but the provider does not deliver the
  claim today; the accessor stays empty until it does, and starts returning it
  with no library change once it lands.

## Development against a local provider

Point `issuer(...)` at your provider instance. The issuer value must match the `iss` inside the
tokens exactly — it is compared, not normalized.

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

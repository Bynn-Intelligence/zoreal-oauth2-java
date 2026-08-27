package com.zoreal.oauth2;

import java.util.List;
import java.util.Map;

import com.nimbusds.jose.jwk.JWKSet;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The Login conveniences over an already-verified claims map. */
class LoginTest {

    private Login login(Map<String, Object> claims) {
        ZorealOAuth2Client client = ZorealOAuth2Client.builder()
                .clientId("ast_test_client")
                .issuer("https://id.zoreal.example")
                .jwksSource(new StaticJwksSource(new JWKSet(List.of())))
                .build();
        return new Login(client, claims, "x", null, null);
    }

    @Test
    void theConveniencesReadTheClaims() {
        Login login = login(Map.of(
                "sub", "7QK3-9F2M-XR84-B5NP",
                "acr", "zoreal.device",
                "amr", List.of("hwk", "face"),
                "age_over_18", true,
                "nationality", "SWE",
                "zoreal", Map.of("trust_tier", "high")));

        assertEquals("7QK3-9F2M-XR84-B5NP", login.sub());
        assertEquals("zoreal.device", login.acr());
        assertEquals(List.of("hwk", "face"), login.amr());
        assertEquals(true, login.ageOver(18).orElseThrow());
        // 21 was never registered, so there is no claim, not a false.
        assertTrue(login.ageOver(21).isEmpty());
        assertEquals("SWE", login.nationality().orElseThrow());
        assertEquals("high", login.assurance().get("trust_tier"));
    }

    @Test
    void noAccessTokenMeansAnEmptyUserinfoNeverAFetch() {
        Login login = login(Map.of("sub", "7QK3-9F2M-XR84-B5NP"));
        assertEquals(Map.of(), login.userinfo());
        assertTrue(login.email().isEmpty());
        assertFalse(login.emailVerified());
        assertTrue(login.portrait().isEmpty());
    }

    @Test
    void absentClaimsComeBackEmptyNotNull() {
        Login login = login(Map.of("sub", "7QK3-9F2M-XR84-B5NP"));
        assertEquals(List.of(), login.amr());
        assertEquals(Map.of(), login.assurance());
        assertTrue(login.nationality().isEmpty());
        assertTrue(login.ageOver(18).isEmpty());
    }
}

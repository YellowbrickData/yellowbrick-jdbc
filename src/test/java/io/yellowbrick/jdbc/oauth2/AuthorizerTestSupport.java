/*
 * MIT License
 *
 * (c) 2025 Yellowbrick Data, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package io.yellowbrick.jdbc.oauth2;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static com.github.tomakehurst.wiremock.stubbing.Scenario.STARTED;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Objects;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

import org.json.JSONObject;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.RegisterExtension;

import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;

import io.yellowbrick.jdbc.DriverConstants;

abstract class AuthorizerTestSupport {

    // Test constants.
    static final String OAUTH2_TEST_CLIENT_ID = "the-client-id";
    static final String OAUTH2_TEST_USER_CODE = "123";
    static final String OAUTH2_TEST_DEVICE_CODE = "abc";
    static final String OAUTH2_TEST_ACCESS_TOKEN = makeToken("access_token");
    static final String OAUTH2_TEST_ID_TOKEN = makeToken("id_token");
    static final String OAUTH2_TEST_REFRESH_TOKEN = makeToken("refresh_token");
    static final String OAUTH2_TEST_ERROR = "not_authorized";
    static final String OAUTH2_TEST_ERROR_DESCRIPTION = "a descriptive error";
    static final long OAUTH2_TEST_TOKEN_EXPIRATION = TimeUnit.SECONDS.toMillis(10);

    // For each test, setup stock properties for OAuth2.
    Properties info;

    @RegisterExtension
    static WireMockExtension wm = new OAuth2WireMockExtension(WireMockExtension.extensionOptions());

    static class OAuth2WireMockExtension extends WireMockExtension {

        OAuth2WireMockExtension(WireMockExtension.Builder builder) {
            super(builder);
        }

        @Override
        protected void onBeforeEach(WireMockRuntimeInfo wireMockRuntimeInfo) {
            stubFor(get(urlEqualTo("/.well-known/openid-configuration"))
                    .withHeader("Accept", containing("application/json"))
                    .willReturn(aResponse()
                            .withHeader("Content-Type", "application/json")
                            .withBody(
                                    toJSON(
                                            "device_authorization_endpoint", wm.url("devicecode"),
                                            "token_endpoint", wm.url("token")))));

            stubFor(post(urlEqualTo("/devicecode"))
                    .withHeader("Content-Type", containing("application/x-www-form-urlencoded"))
                    .withRequestBody(containing("client_id=" + OAUTH2_TEST_CLIENT_ID))
                    .withRequestBody(containing("scope="))
                    .willReturn(aResponse()
                            .withHeader("Content-Type", "application/json")
                            .withBody(
                                    toJSON(
                                            "device_code", OAUTH2_TEST_DEVICE_CODE,
                                            "user_code", OAUTH2_TEST_USER_CODE,
                                            "verification_uri", wm.url("verify"),
                                            "expires_in", 10,
                                            "interval", 1))));

            stubFor(post(urlEqualTo("/token"))
                    .inScenario("TokenFlow")
                    .whenScenarioStateIs("SUCCESS")
                    .withHeader("Content-Type", containing("application/x-www-form-urlencoded"))
                    .withRequestBody(containing("grant_type=urn:ietf:params:oauth:grant-type:device_code"))
                    .withRequestBody(containing("device_code=" + OAUTH2_TEST_DEVICE_CODE))
                    .withRequestBody(containing("client_id=" + OAUTH2_TEST_CLIENT_ID))
                    .willReturn(aResponse()
                            .withStatus(400)
                            .withBody(
                                    toJSON(
                                            "error", "authorization_pending")))
                    .willSetStateTo("PENDING"));

            stubFor(post(urlEqualTo("/token"))
                    .inScenario("TokenFlow")
                    .whenScenarioStateIs("PENDING")
                    .withHeader("Content-Type", containing("application/x-www-form-urlencoded"))
                    .withRequestBody(containing("grant_type=urn:ietf:params:oauth:grant-type:device_code"))
                    .withRequestBody(containing("device_code=" + OAUTH2_TEST_DEVICE_CODE))
                    .withRequestBody(containing("client_id=" + OAUTH2_TEST_CLIENT_ID))
                    .willReturn(aResponse()
                            .withBody(
                                    toJSON(
                                            "access_token", OAUTH2_TEST_ACCESS_TOKEN,
                                            "id_token", OAUTH2_TEST_ID_TOKEN,
                                            "refresh_token", OAUTH2_TEST_REFRESH_TOKEN)))
                    .willSetStateTo("AUTHORIZED"));

            stubFor(post(urlEqualTo("/token"))
                    .inScenario("TokenFlow")
                    .whenScenarioStateIs("ERROR")
                    .withHeader("Content-Type", containing("application/x-www-form-urlencoded"))
                    .withRequestBody(containing("grant_type=urn:ietf:params:oauth:grant-type:device_code"))
                    .withRequestBody(containing("device_code=" + OAUTH2_TEST_DEVICE_CODE))
                    .withRequestBody(containing("client_id=" + OAUTH2_TEST_CLIENT_ID))
                    .willReturn(aResponse()
                            .withStatus(400)
                            .withBody(
                                    toJSON(
                                            "error", OAUTH2_TEST_ERROR,
                                            "error_description", OAUTH2_TEST_ERROR_DESCRIPTION))));

            stubFor(post(urlEqualTo("/token"))
                    .inScenario("TokenFlow")
                    .whenScenarioStateIs("TIMEOUT")
                    .withHeader("Content-Type", containing("application/x-www-form-urlencoded"))
                    .withRequestBody(containing("grant_type=urn:ietf:params:oauth:grant-type:device_code"))
                    .withRequestBody(containing("device_code=" + OAUTH2_TEST_DEVICE_CODE))
                    .withRequestBody(containing("client_id=" + OAUTH2_TEST_CLIENT_ID))
                    .willReturn(aResponse()
                            .withStatus(400)
                            .withBody(
                                    toJSON(
                                            "error", "authorization_pending")))
                    .willSetStateTo("TIMEOUT"));

            stubFor(post(urlEqualTo("/token"))
                    .inScenario("TokenFlowRefresh")
                    .whenScenarioStateIs(STARTED)
                    .withHeader("Content-Type", containing("application/x-www-form-urlencoded"))
                    .withRequestBody(containing("grant_type=refresh_token"))
                    .withRequestBody(containing(
                            "refresh_token=" + URLEncoder.encode(OAUTH2_TEST_REFRESH_TOKEN, StandardCharsets.UTF_8)))
                    .withRequestBody(containing("client_id=" + OAUTH2_TEST_CLIENT_ID))
                    .willReturn(aResponse()
                            .withBody(
                                    toJSON(
                                            "access_token", OAUTH2_TEST_ACCESS_TOKEN,
                                            "id_token", OAUTH2_TEST_ID_TOKEN)))
                    .willSetStateTo("REFRESHED"));
        }
    }

    @BeforeEach
    void setupProperties() {
        info = new Properties();
        info.setProperty(DriverConstants.YB_JDBC_OAUTH2_ISSUER, wm.baseUrl());
        info.setProperty(DriverConstants.YB_JDBC_OAUTH2_CLIENT_ID, OAUTH2_TEST_CLIENT_ID);
        info.setProperty(DriverConstants.YB_JDBC_OAUTH2_NO_BROWSER, Boolean.TRUE.toString());
        info.setProperty(DriverConstants.YB_JDBC_OAUTH2_QUIET, Boolean.TRUE.toString());
    }

    static String makeToken(String tokenType) {
        long expiration = TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis() + OAUTH2_TEST_TOKEN_EXPIRATION);
        String payload = toJSON(
                "exp", expiration,
                "typ", tokenType);
        return "header." + Base64.getUrlEncoder().encodeToString(payload.getBytes()) + ".signature";
    }

    static String toJSON(Object... keyValues) {
        if (keyValues.length % 2 != 0) {
            throw new IllegalArgumentException("Must provide even number of arguments (key-value pairs)");
        }

        JSONObject obj = new JSONObject();
        for (int i = 0; i < keyValues.length; i += 2) {
            obj.put(String.valueOf(keyValues[i]), keyValues[i + 1]);
        }
        return obj.toString(2);
    }

    long stateCount(String state) {
        return wm.getAllServeEvents().stream()
                .filter(r -> Objects.equals(r.getStubMapping().getNewScenarioState(), state)).count();
    }

    void assertState(String state, long expectedCount) {
        long actualCount = stateCount(state);
        assertTrue(actualCount == expectedCount, "Expected count: " + expectedCount + ", actual count: " + actualCount);
    }
}

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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.SQLException;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.github.tomakehurst.wiremock.junit5.WireMockTest;

import io.yellowbrick.jdbc.DriverConfiguration;
import io.yellowbrick.jdbc.DriverConstants;

@WireMockTest
class OAuth2AuthorizerTests extends AuthorizerTestSupport {

    @Test
    @DisplayName("Authenticate With OAuth2 Device Code, ID Token")
    void testAuthIdToken() {
        wm.setScenarioState("TokenFlow", "SUCCESS");
        assertDoesNotThrow(() -> {
            OAuth2Authorizer auth2Authorizer = new OAuth2Authorizer(new DriverConfiguration(info), OAUTH2_TEST_CLIENT_ID, info);
            Token accessToken = auth2Authorizer.getOAuth2AccessToken();
            assertEquals(accessToken.getAuthToken(), OAUTH2_TEST_ID_TOKEN);
        });
        assertState("AUTHORIZED", 1);
    }

    @Test
    @DisplayName("Authenticate With OAuth2 Device Code, Access Token")
    void testAuthAccessToken() {
        wm.setScenarioState("TokenFlow", "SUCCESS");
        assertDoesNotThrow(() -> {
            info.setProperty(DriverConstants.YB_JDBC_OAUTH2_TOKEN_TYPE, DriverConstants.YB_JDBC_OAUTH2_TOKEN_TYPE_ACCESS_TOKEN);
            OAuth2Authorizer auth2Authorizer = new OAuth2Authorizer(new DriverConfiguration(info), OAUTH2_TEST_CLIENT_ID, info);
            Token accessToken = auth2Authorizer.getOAuth2AccessToken();
            assertEquals(accessToken.getAuthToken(), OAUTH2_TEST_ACCESS_TOKEN);
        });
        assertState("AUTHORIZED", 1);
    }

    @Test
    @DisplayName("Authenticate With OAuth2 Device Code, Not Authorized")
    void testAuthNotAuthorized() {
        wm.setScenarioState("TokenFlow", "ERROR");
        SQLException ex = assertThrows(SQLException.class, () -> {
            OAuth2Authorizer auth2Authorizer = new OAuth2Authorizer(new DriverConfiguration(info), OAUTH2_TEST_CLIENT_ID, info);
            auth2Authorizer.getOAuth2AccessToken();
        });
        assertTrue(ex.getMessage().contains("error: " + OAUTH2_TEST_ERROR));
        assertTrue(ex.getMessage().contains("description: " + OAUTH2_TEST_ERROR_DESCRIPTION));
        assertState("AUTHORIZED", 0);
    }

    @Test
    @DisplayName("Authenticate With OAuth2 Device Code, Expired")
    void testAuthExpired() {
        wm.setScenarioState("TokenFlow", "TIMEOUT");
        SQLException ex = assertThrows(SQLException.class, () -> {
            OAuth2Authorizer auth2Authorizer = new OAuth2Authorizer(new DriverConfiguration(info), OAUTH2_TEST_CLIENT_ID, info);
            auth2Authorizer.getOAuth2AccessToken();
        });
        assertTrue(ex.getMessage().contains("Device authentication expired"));
        assertState("AUTHORIZED", 0);
        long timeoutCount = stateCount("TIMEOUT");
        assertTrue(timeoutCount > 3, "Expected timeout count: > " + 3 + ", actual timeout count: " + timeoutCount);
    }

    @Test
    @DisplayName("Authenticate With OAuth2 Device Code, With Refresh")
    void testAuthRefresh() {
        AtomicReference<String> refreshToken = new AtomicReference<>();
        wm.setScenarioState("TokenFlow", "SUCCESS");
        assertDoesNotThrow(() -> {
            info.setProperty(DriverConstants.YB_JDBC_OAUTH2_SCOPES, DriverConstants.YB_JDBC_OAUTH2_SCOPES_DEFAULT);
            OAuth2Authorizer auth2Authorizer = new OAuth2Authorizer(new DriverConfiguration(info), OAUTH2_TEST_CLIENT_ID, info);
            Token token = auth2Authorizer.getOAuth2AccessToken();
            refreshToken.set(token.getRefreshToken());
        });
        assertState("AUTHORIZED", 1);
        assertDoesNotThrow(() -> {
            OAuth2Authorizer auth2Authorizer = new OAuth2Authorizer(new DriverConfiguration(info), OAUTH2_TEST_CLIENT_ID, info);
            Token token = auth2Authorizer.refreshOAuth2AccessToken(refreshToken.get());
            assertEquals(token.getAuthToken(), OAUTH2_TEST_ID_TOKEN);
        });
        assertState("REFRESHED", 1);
    }
}

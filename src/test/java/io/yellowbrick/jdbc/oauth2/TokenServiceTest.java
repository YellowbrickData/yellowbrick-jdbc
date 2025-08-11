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
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.time.Instant;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.github.tomakehurst.wiremock.junit5.WireMockTest;

import io.yellowbrick.jdbc.DriverConfiguration;
import io.yellowbrick.jdbc.DriverConstants;

@WireMockTest
class TokenServiceTest extends AuthorizerTestSupport {
    final static String TOKENSERVICE_TEST_URL = "jdbc:yb://host:5432/database";
    final static String TOKENSERVICE_TEST_URL2 = "jdbc:yb://host:5432/database2";

    @BeforeAll
    static void enableTokenCacheTestPersistence() {
        TokenService.CACHE_FILE_NAME = "token-cache-test.json";
        TokenService.getInstance().deleteTokenCache();
    }

    @AfterAll
    static void cleanupTokenCacheTestPersistence() {
        TokenService.getInstance().deleteTokenCache();
    }

    @Test
    @DisplayName("Access Token Cache, Memory Cache Mode")
    void testTokenCacheInMemory() {
        wm.setScenarioState("TokenFlow", "SUCCESS");
        info.setProperty(DriverConstants.YB_JDBC_OAUTH2_TOKEN_CACHE, DriverConstants.YB_JDBC_OAUTH2_TOKEN_CACHE_MEMORY);
        DriverConfiguration driverConfiguration = new DriverConfiguration(info);
        assertDoesNotThrow(() -> {
            TokenService.getInstance().getToken(driverConfiguration, TOKENSERVICE_TEST_URL, info);
        });
        wm.setScenarioState("TokenFlow", "SUCCESS");
        assertDoesNotThrow(() -> {
            TokenService.getInstance().getToken(driverConfiguration, TOKENSERVICE_TEST_URL, info);
        });
        assertState("AUTHORIZED", 1);
    }

    @Test
    @DisplayName("Access Token Cache, Memory Cache Mode, Refresh")
    void testTokenCacheInMemoryWithRefresh() {
        wm.setScenarioState("TokenFlow", "SUCCESS");
        info.setProperty(DriverConstants.YB_JDBC_OAUTH2_TOKEN_CACHE, DriverConstants.YB_JDBC_OAUTH2_TOKEN_CACHE_MEMORY);
        DriverConfiguration driverConfiguration = new DriverConfiguration(info);
        assertDoesNotThrow(() -> {
            Token accessToken = TokenService.getInstance().getToken(driverConfiguration, TOKENSERVICE_TEST_URL, info);
            while (accessToken.getExpiresAt().isAfter(Instant.now())) {
                TimeUnit.SECONDS.sleep(1);
            }
        });
        wm.setScenarioState("TokenFlow", "SUCCESS");
        assertDoesNotThrow(() -> {
            TokenService.getInstance().getToken(driverConfiguration, TOKENSERVICE_TEST_URL, info);
        });
        assertState("AUTHORIZED", 1);
        assertState("REFRESHED", 1);
    }

    @Test
    @DisplayName("Access Token Cache, File Cache Mode, Refresh")
    void testTokenCacheFileWithRefresh() {
        wm.setScenarioState("TokenFlow", "SUCCESS");
        info.setProperty(DriverConstants.YB_JDBC_OAUTH2_TOKEN_CACHE, DriverConstants.YB_JDBC_OAUTH2_TOKEN_CACHE_FILE);
        DriverConfiguration driverConfiguration = new DriverConfiguration(info);
        assertDoesNotThrow(() -> {
            Token accessToken = TokenService.getInstance().getToken(driverConfiguration, TOKENSERVICE_TEST_URL, info);
            while (accessToken.getExpiresAt().isAfter(Instant.now())) {
                TimeUnit.SECONDS.sleep(1);
            }
        });
        TokenService.getInstance().clearTokenCache();
        wm.setScenarioState("TokenFlow", "SUCCESS");
        assertDoesNotThrow(() -> {
            TokenService.getInstance().getToken(driverConfiguration, TOKENSERVICE_TEST_URL, info);
        });
        assertState("AUTHORIZED", 1);
        assertState("REFRESHED", 1);
    }

    @Test
    @DisplayName("Access Token Cache, File Cache Mode, 2 Databases")
    void testTokenCache2Databases() {
        wm.setScenarioState("TokenFlow", "SUCCESS");
        info.setProperty(DriverConstants.YB_JDBC_OAUTH2_TOKEN_CACHE, DriverConstants.YB_JDBC_OAUTH2_TOKEN_CACHE_FILE);
        DriverConfiguration driverConfiguration = new DriverConfiguration(info);
        assertDoesNotThrow(() -> {
            Token accessToken1 = TokenService.getInstance().getToken(driverConfiguration, TOKENSERVICE_TEST_URL, info);
            Token accessToken2 = TokenService.getInstance().getToken(driverConfiguration, TOKENSERVICE_TEST_URL2, info);
            assertNotNull(accessToken1);
            assertNotNull(accessToken2);
            assertEquals(accessToken1.getAuthToken(), accessToken2.getAuthToken());
        });
        assertState("AUTHORIZED", 1);
    }

    @Test
    @DisplayName("Access Token Cache, Cache Disabled")
    void testTokenCacheDisabled() {
        wm.setScenarioState("TokenFlow", "SUCCESS");
        info.setProperty(
                DriverConstants.YB_JDBC_OAUTH2_TOKEN_CACHE,
                DriverConstants.YB_JDBC_OAUTH2_TOKEN_CACHE_DISABLED);
        DriverConfiguration driverConfiguration = new DriverConfiguration(info);
        assertDoesNotThrow(() -> {
            TokenService.getInstance().getToken(driverConfiguration, TOKENSERVICE_TEST_URL, info);
        });
        wm.setScenarioState("TokenFlow", "SUCCESS");
        assertDoesNotThrow(() -> {
            TokenService.getInstance().getToken(driverConfiguration, TOKENSERVICE_TEST_URL, info);
        });
        assertState("AUTHORIZED", 2);
    }
}

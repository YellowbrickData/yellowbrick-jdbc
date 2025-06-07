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
package io.yellowbrick.jdbc;

import java.util.Properties;


public class DriverConfiguration {

    public enum TokenCacheOption {
        MEMORY,
        FILE,
        DISABLED;

        public static TokenCacheOption fromString(String value) {
            if (value == null)
                return MEMORY; // Default
            switch (value.toLowerCase()) {
                case "memory":
                    return MEMORY;
                case "file":
                    return FILE;
                case "disabled":
                    return DISABLED;
                default:
                    throw new IllegalArgumentException("Invalid token cache option: " + value);
            }
        }
    }

    public enum TokenType {
        ID_TOKEN("id-token"),
        ACCESS_TOKEN("access-token");

        private final String value;

        TokenType(String value) {
            this.value = value;
        }

        public String value() {
            return value;
        }

        public static TokenType fromString(String value) {
            if (value == null)
                return ID_TOKEN; // Default
            for (TokenType t : values()) {
                if (t.value.equalsIgnoreCase(value)) {
                    return t;
                }
            }
            throw new IllegalArgumentException("Invalid token type: " + value);
        }
    }

    // OAuth2 client configuration
    public final String clientId;
    public final String clientSecret;
    public final String issuer;
    public final String loginHint;
    public final String scopes;
    public final TokenType tokenType;
    public final TokenCacheOption tokenCache;
    public final boolean noBrowser;
    public final boolean quiet; // test only, and only if noBrowser is true
    public final String cacertPath;
    public final boolean disableTrust;

    public DriverConfiguration(Properties info) {
        this.clientId = info.getProperty(DriverConstants.YB_JDBC_OAUTH2_CLIENT_ID);
        this.clientSecret = info.getProperty(DriverConstants.YB_JDBC_OAUTH2_CLIENT_SECRET);
        this.issuer = info.getProperty(DriverConstants.YB_JDBC_OAUTH2_ISSUER);
        this.loginHint = info.getProperty(DriverConstants.YB_JDBC_OAUTH2_LOGIN_HINT);
        this.scopes = info.getProperty(
                DriverConstants.YB_JDBC_OAUTH2_SCOPES,
                DriverConstants.YB_JDBC_OAUTH2_SCOPES_DEFAULT);
        this.tokenType = TokenType.fromString(info.getProperty(
                DriverConstants.YB_JDBC_OAUTH2_TOKEN_TYPE, 
                DriverConstants.YB_JDBC_OAUTH2_TOKEN_TYPE_DEFAULT));
        this.tokenCache = TokenCacheOption.fromString(info.getProperty(
                DriverConstants.YB_JDBC_OAUTH2_TOKEN_CACHE, 
                DriverConstants.YB_JDBC_OAUTH2_TOKEN_CACHE_DEFAULT));
        this.noBrowser = Boolean.parseBoolean(info.getProperty(
                DriverConstants.YB_JDBC_OAUTH2_NO_BROWSER, "false"));
        this.quiet = Boolean.parseBoolean(info.getProperty(
                DriverConstants.YB_JDBC_OAUTH2_QUIET, "false"));
        this.cacertPath = info.getProperty(DriverConstants.YB_JDBC_OAUTH2_CACERT_PATH);
        this.disableTrust = Boolean.parseBoolean(info.getProperty(
                DriverConstants.YB_JDBC_OAUTH2_DISABLE_TRUST, "false"));
    }
}

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


public interface DriverConstants {
    // JDBC URL prefixes
    String YB_URL_PREFIX = "jdbc:yb:";
    String PG_URL_PREFIX = "jdbc:postgresql:";

    // OAuth2 client configuration
    String YB_JDBC_OAUTH2_CLIENT_ID = "oauth2ClientId";
    String YB_JDBC_OAUTH2_CLIENT_SECRET = "oauth2ClientSecret";
    String YB_JDBC_OAUTH2_ISSUER = "oauth2Issuer";

    // Optional login hint (e.g., to prefill username)
    String YB_JDBC_OAUTH2_LOGIN_HINT = "oauth2LoginHint";

    // Optional audience
    String YB_JDBC_OAUTH2_AUDIENCE = "oauth2Audience";

    // Scopes for access token requests
    String YB_JDBC_OAUTH2_SCOPES = "oauth2Scopes";
    String YB_JDBC_OAUTH2_SCOPES_DEFAULT = "openid email profile offline_access";

    // Token to use for authorization token in connect()
    String YB_JDBC_OAUTH2_TOKEN_TYPE = "oauth2TokenType";
    String YB_JDBC_OAUTH2_TOKEN_TYPE_ACCESS_TOKEN = "access-token";
    String YB_JDBC_OAUTH2_TOKEN_TYPE_ID_TOKEN = "id-token";
    String YB_JDBC_OAUTH2_TOKEN_TYPE_DEFAULT = YB_JDBC_OAUTH2_TOKEN_TYPE_ID_TOKEN;
    String[] YB_JDBC_OAUTH2_TOKEN_OPTIONS = {
        YB_JDBC_OAUTH2_TOKEN_TYPE_ACCESS_TOKEN,
        YB_JDBC_OAUTH2_TOKEN_TYPE_ID_TOKEN
    };

    // How to cache tokens
    String YB_JDBC_OAUTH2_TOKEN_CACHE = "oauth2TokenCache";
    String YB_JDBC_OAUTH2_TOKEN_CACHE_MEMORY = "memory";
    String YB_JDBC_OAUTH2_TOKEN_CACHE_FILE = "file";
    String YB_JDBC_OAUTH2_TOKEN_CACHE_DISABLED = "disabled";
    String[] YB_JDBC_OAUTH2_TOKEN_CACHE_OPTIONS = {
        YB_JDBC_OAUTH2_TOKEN_CACHE_MEMORY,
        YB_JDBC_OAUTH2_TOKEN_CACHE_FILE,
        YB_JDBC_OAUTH2_TOKEN_CACHE_DISABLED
    };
    String YB_JDBC_OAUTH2_TOKEN_CACHE_DEFAULT = YB_JDBC_OAUTH2_TOKEN_CACHE_MEMORY;

    // What interaction mode to use
    String YB_JDBC_OAUTH2_INTERACTION_MODE = "oauth2InteractionMode";
    String YB_JDBC_OAUTH2_INTERACTION_MODE_DIALOG = "dialog";
    String YB_JDBC_OAUTH2_INTERACTION_MODE_BROWSER = "browser";
    String YB_JDBC_OAUTH2_INTERACTION_MODE_CONSOLE = "console";
    String YB_JDBC_OAUTH2_INTERACTION_MODE_DEFAULT = YB_JDBC_OAUTH2_INTERACTION_MODE_DIALOG;
    String[] YB_JDBC_OAUTH2_INTERACTION_MODE_OPTIONS = {
        YB_JDBC_OAUTH2_INTERACTION_MODE_DIALOG,
        YB_JDBC_OAUTH2_INTERACTION_MODE_BROWSER,
        YB_JDBC_OAUTH2_INTERACTION_MODE_CONSOLE
    };

    // Path to custom CA certificate (PEM)
    String YB_JDBC_OAUTH2_CACERT_PATH = "oauth2CAcertPath";

    // Disable trust to issuer URL (for testing purposes)
    String YB_JDBC_OAUTH2_DISABLE_TRUST = "oauth2SSLDisableTrust";

    // Miscellaneous properties
    String YB_JDBC_OAUTH2_QUIET = "oauth2Quiet"; // test only
}

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

import java.net.URI;
import java.net.URISyntaxException;
import java.sql.SQLException;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;

import org.json.JSONObject;

import io.yellowbrick.jdbc.DriverConfiguration;
import io.yellowbrick.jdbc.DriverConfiguration.TokenCacheOption;
import io.yellowbrick.jdbc.DriverConstants;    


/**
 * Represents an OAuth2 token used for authentication with the Yellowbrick database.
 * This class encapsulates the access or id token, refresh token, expiration time, and
 * additional properties used to obtain the connection.
 */
public class Token {
    private final String authToken; // This is the access token OR id token, depending on the type
    private final String refreshToken; // ONLY if scope includes "offline_access"
    private final Instant expiresAt; // Expiration time of the auth token
    private final String connection; // Connection information for the token
    private final Properties info; // Additional properties used to obtain the connection

    public static Token createToken(String authToken, String refreshToken, Instant expiresAt, String url, Properties info) throws SQLException {
        return new Token(authToken, refreshToken, expiresAt, extractConnectionInfo(url), info);
    }

    private Token(String authToken, String refreshToken, Instant expiresAt, String connection, Properties info) {
        this.authToken = authToken;
        this.refreshToken = refreshToken;
        this.expiresAt = expiresAt;
        this.connection = connection;

        // All the info properties except password.
        this.info = copyOf(info);
    }

    public String getAuthToken() {
        return authToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public String getConnection() {
        return connection;
    }

    public Properties getInfo() {
        return info;
    }

    public TokenCacheOption getTokenCacheOption() {
        return DriverConfiguration.TokenCacheOption.fromString(info.getProperty(DriverConstants.YB_JDBC_OAUTH2_TOKEN_CACHE, DriverConstants.YB_JDBC_OAUTH2_TOKEN_CACHE_DEFAULT));
    }

    public static Properties copyOf(Properties info) {
        Properties result = new Properties();
        for (String key : info.stringPropertyNames()) {
            if (!key.equalsIgnoreCase("password")) {
                result.setProperty(key, info.getProperty(key));
            }
        }
        return result;
    }

    public boolean matches(String connection, Properties info) {
        return this.connection.equals(connection) && Objects.equals(this.info, copyOf(info));
    }

    public JSONObject toJSONObject() {
        JSONObject json = new JSONObject();
        json.put("authToken", authToken);
        json.put("refreshToken", refreshToken);
        json.put("expiresAt", expiresAt != null ? expiresAt.toString() : null); // ISO 8601 string
        json.put("connection", connection);
        JSONObject infoJson = new JSONObject();
        for (Map.Entry<Object, Object> entry : info.entrySet()) {
            infoJson.put(entry.getKey().toString(), entry.getValue().toString());
        }
        json.put("info", infoJson);
        return json;
    }

    public static Token fromJSONObject(JSONObject json) throws SQLException {
        String authToken = json.optString("authToken", null);
        String refreshToken = json.optString("refreshToken", null);
        String expiresAtStr = json.optString("expiresAt", null);
        Instant expiresAt = (expiresAtStr != null) ? Instant.parse(expiresAtStr) : null;
        String connection = json.optString("connection", null);
        if (connection == null) {
            String url = json.optString("url", null); // attempt fallback
            if (url != null) {
                connection = extractConnectionInfo(url);
            }
        }
        Properties info = new Properties();
        JSONObject infoJson = json.optJSONObject("info");
        if (infoJson != null) {
            Map<String, Object> infoMap = infoJson.toMap();
            for (Map.Entry<String, Object> entry : infoMap.entrySet()) {
                info.setProperty(entry.getKey(), entry.getValue().toString());
            }
        }
        return new Token(authToken, refreshToken, expiresAt, connection, info);
    }

    /** 
     * Build connection key from host + port + url parameters
     *
     * Why? the identity here is for the user, not the database.  A user either has the privilege
     *      to CONNECT to the database or not, but the same token can be used for any target
     *      database.
     * @throws SQLException
     */
    static String extractConnectionInfo(String jdbcUrl) throws SQLException {
        try {
            // Remove the jdbc: prefix for URI parsing
            if (!jdbcUrl.startsWith("jdbc:")) {
                throw new SQLException("Invalid JDBC URL: must start with 'jdbc:'");
            }
            String rawUrl = jdbcUrl.substring(5);

            // Fixup proper URI format which must include //
            rawUrl = rawUrl.replaceFirst("^(?i)(postgresql|yb):(?=[^/]*:)", "$1://");

            // Append scheme:host:port?queryParameters
            URI uri = new URI(rawUrl);
            StringBuilder result = new StringBuilder();
            if (uri.getHost() == null) {
                throw new SQLException(String.format("Could not parse JDBC URL: %s", jdbcUrl));
            }
            result.append(uri.getScheme()).append(":").append(uri.getHost());
            if (uri.getPort() != -1) {
                result.append(":").append(uri.getPort());
            }
            if (uri.getQuery() != null) {
                result.append("?").append(uri.getQuery());
            }
            return result.toString();
        } catch (URISyntaxException e) {
            throw new SQLException("Failed to parse JDBC URL: " + jdbcUrl, e);
        }
    }
}

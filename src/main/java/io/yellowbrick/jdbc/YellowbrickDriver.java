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

import java.sql.Connection;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.DriverPropertyInfo;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Properties;
import java.util.logging.Logger;

import io.yellowbrick.jdbc.oauth2.Token;
import io.yellowbrick.jdbc.oauth2.TokenService;


public class YellowbrickDriver implements Driver, DriverConstants {

    static {
        try {
            DriverManager.registerDriver(new YellowbrickDriver());
        } catch (SQLException e) {
            throw new RuntimeException("Failed to register driver", e);
        }
    }

    private final Driver delegate;

    public YellowbrickDriver() {
        try {
            this.delegate = (Driver) Class
                    .forName("io.yellowbrick.shaded.org.postgresql.Driver")
                    .getDeclaredConstructor()
                    .newInstance();
        } catch (Exception e) {
            throw new RuntimeException("Unable to load shaded PostgreSQL driver", e);
        }
    }

    @Override
    public Connection connect(String url, Properties info) throws SQLException {
        if (!acceptsURL(url)) {
            return null;
        }

        String rewrittenUrl = url;

        // Rewrite jdbc:yb: to jdbc:postgresql:
        if (url.startsWith(YB_URL_PREFIX)) {
            rewrittenUrl = PG_URL_PREFIX + url.substring(YB_URL_PREFIX.length());
        }

        // Extract custom OAuth2 parameters
        String issuer = info.getProperty(YB_JDBC_OAUTH2_ISSUER);
        String clientId = info.getProperty(YB_JDBC_OAUTH2_CLIENT_ID);
        if (issuer != null && clientId != null) {
            DriverConfiguration driverConfiguration = new DriverConfiguration(info);

            // Get an access token using the TokenService
            Token token = TokenService.getInstance(driverConfiguration).getToken(driverConfiguration, url, info);
            if (token == null) {
                throw new SQLException("Failed to obtain OAuth2 access token");
            }

            // Make a copy of the info properties to avoid modifying the original
            Properties infoCopy = new Properties();
            infoCopy.putAll(info);
            infoCopy.put("user", String.format("jwt:%s", token.getAuthToken()));
            infoCopy.put("password", ""); // Password is not needed for OAuth2 with Yellowbrick
            info = infoCopy;
        }

        return delegate.connect(rewrittenUrl, info);
    }

    @Override
    public boolean acceptsURL(String url) {
        return url != null &&
                (url.startsWith(YB_URL_PREFIX) || url.startsWith(PG_URL_PREFIX));
    }

    @Override
    public DriverPropertyInfo[] getPropertyInfo(String url, Properties info) throws SQLException {
        List<DriverPropertyInfo> props = new ArrayList<>();

        // OAuth2 issuer
        DriverPropertyInfo authIssuer = new DriverPropertyInfo(YB_JDBC_OAUTH2_ISSUER, info.getProperty(YB_JDBC_OAUTH2_ISSUER));
        authIssuer.description = "The OAuth2 issuer URL. Required for OAuth2 endpoint discovery.";
        authIssuer.required = true;
        props.add(authIssuer);

        // OAuth2 client ID
        DriverPropertyInfo clientId = new DriverPropertyInfo(YB_JDBC_OAUTH2_CLIENT_ID, info.getProperty(YB_JDBC_OAUTH2_CLIENT_ID));
        clientId.description = "OAuth2 client ID for authentication. Must be registered with the issuer.";
        clientId.required = true;
        props.add(clientId);

        // OAuth2 client secret
        DriverPropertyInfo clientSecret = new DriverPropertyInfo(YB_JDBC_OAUTH2_CLIENT_SECRET, info.getProperty(YB_JDBC_OAUTH2_CLIENT_SECRET));
        clientSecret.description = "Optional OAuth2 client secret (used for confidential clients).";
        clientSecret.required = false;
        props.add(clientSecret);

        // Optional login hint
        DriverPropertyInfo loginHint = new DriverPropertyInfo(YB_JDBC_OAUTH2_LOGIN_HINT, info.getProperty(YB_JDBC_OAUTH2_LOGIN_HINT));
        loginHint.description = "Optional login_hint to suggest the user's identity to the OAuth2 provider.";
        loginHint.required = false;
        props.add(loginHint);

        // OAuth2 scopes
        String scopesValue = info.getProperty(YB_JDBC_OAUTH2_SCOPES, YB_JDBC_OAUTH2_SCOPES_DEFAULT);
        DriverPropertyInfo scopes = new DriverPropertyInfo(YB_JDBC_OAUTH2_SCOPES, scopesValue);
        scopes.description = "Space-separated OAuth2 scopes to request. Default is: " + YB_JDBC_OAUTH2_SCOPES_DEFAULT;
        scopes.required = false;
        props.add(scopes);

        // Token type
        String tokenTypeValue = info.getProperty(YB_JDBC_OAUTH2_TOKEN_TYPE, YB_JDBC_OAUTH2_TOKEN_TYPE_DEFAULT);
        DriverPropertyInfo tokenType = new DriverPropertyInfo(YB_JDBC_OAUTH2_TOKEN_TYPE, tokenTypeValue);
        tokenType.description = "OAuth2 token type to use for login. Default is: " + YB_JDBC_OAUTH2_TOKEN_TYPE_DEFAULT;
        tokenType.choices = YB_JDBC_OAUTH2_TOKEN_OPTIONS;
        tokenType.required = false;
        props.add(tokenType);

        // Token cache
        String tokenCacheValue = info.getProperty(YB_JDBC_OAUTH2_TOKEN_CACHE, YB_JDBC_OAUTH2_TOKEN_CACHE_DEFAULT);
        DriverPropertyInfo tokenCache = new DriverPropertyInfo(YB_JDBC_OAUTH2_TOKEN_CACHE, tokenCacheValue);
        tokenCache.description = "OAuth2 token cache to use for handling sessions. Default is: " + YB_JDBC_OAUTH2_TOKEN_CACHE_DEFAULT;
        tokenCache.choices = YB_JDBC_OAUTH2_TOKEN_CACHE_OPTIONS;
        tokenCache.required = false;
        props.add(tokenCache);

        // Custom CA certificate
        DriverPropertyInfo cacertPath = new DriverPropertyInfo(YB_JDBC_OAUTH2_CACERT_PATH, info.getProperty(YB_JDBC_OAUTH2_CACERT_PATH));
        cacertPath.description = "Path to a custom CA certificate file to verify the issuer's TLS certificate.";
        cacertPath.required = false;
        props.add(cacertPath);

        // No browser option
        DriverPropertyInfo noBrowser = new DriverPropertyInfo(YB_JDBC_OAUTH2_NO_BROWSER, info.getProperty(YB_JDBC_OAUTH2_NO_BROWSER));
        noBrowser.description = "If true, do not attempt to open a browser for device code login.  For command line tools that display stdout.  Default is false.";
        noBrowser.required = false;
        noBrowser.choices = new String[]{"true", "false"};
        props.add(noBrowser);

        // Add properties from the underlying PostgreSQL driver
        Collections.addAll(props, delegate.getPropertyInfo(url, info));

        return props.toArray(new DriverPropertyInfo[0]);
    }

    @Override
    public int getMajorVersion() {
        return delegate.getMajorVersion();
    }

    @Override
    public int getMinorVersion() {
        return delegate.getMinorVersion();
    }

    @Override
    public boolean jdbcCompliant() {
        return delegate.jdbcCompliant();
    }

    @Override
    public Logger getParentLogger() {
        return Logger.getGlobal();
    }
}

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

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.sql.SQLException;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.json.JSONException;
import org.json.JSONObject;

import io.yellowbrick.jdbc.DriverConfiguration;
import io.yellowbrick.jdbc.DriverConstants;
import io.yellowbrick.jdbc.web.DeviceCodeServer;

public class OAuth2Authorizer implements DriverConstants {
    private static final String ENCODING_JSON = "application/json";
    private static final String ENCODING_FORM_URLENCODED = "application/x-www-form-urlencoded";
    private final DriverConfiguration driverConfiguration;
    private final String url;
    private final Properties info;

    public OAuth2Authorizer(DriverConfiguration driverConfiguration, String url, Properties info) throws SQLException {
        this.driverConfiguration = new DriverConfiguration(info);
        this.url = url;
        this.info = info;
        if (driverConfiguration.clientId == null) {
            throw new SQLException("Missing required OAuth2 parameter: " + YB_JDBC_OAUTH2_CLIENT_ID);
        }
        if (driverConfiguration.issuer == null) {
            throw new SQLException("Missing required OAuth2 parameter: " + YB_JDBC_OAUTH2_ISSUER);
        }
    }

    public Token getOAuth2AccessToken() throws SQLException {
        DeviceCodeServer server = null;
        try {
            Endpoints endpoints = getAuthorizationEndpoints();

            // Build HttpClient
            HttpClient.Builder clientBuilder = HttpClient.newBuilder();
            SSLContext sslContext = createSSLContext();
            clientBuilder.sslContext(sslContext);
            HttpClient httpClient = clientBuilder.build();

            // Prepare device auth payload
            Map<String, Object> devicePayloadParams = new HashMap<>(Map.of(
                    "client_id", driverConfiguration.clientId,
                    "scope", driverConfiguration.scopes));
            if (driverConfiguration.loginHint != null) {
                devicePayloadParams.put("login_hint", driverConfiguration.loginHint);
            }
            String devicePayload = FormParameterEncoder.toFormEncoding(devicePayloadParams);

            // Send device auth request
            HttpRequest deviceRequest = HttpRequest.newBuilder()
                    .uri(URI.create(endpoints.deviceEndpoint))
                    .header("Content-Type", ENCODING_FORM_URLENCODED)
                    .header("Accept", ENCODING_JSON)
                    .POST(HttpRequest.BodyPublishers.ofString(devicePayload))
                    .build();

            HttpResponse<String> deviceResponse = httpClient.send(deviceRequest, HttpResponse.BodyHandlers.ofString());
            if (deviceResponse.statusCode() != 200) {
                if (deviceResponse.statusCode() == 400) {
                    System.err
                            .println("WARNING: Device login has been disabled for Yellowbrick by your administrator.");
                    System.err.printf("RESPONSE: %s\n", deviceResponse.body());
                    return null;
                } else {
                    throw new SQLException(
                            "Invalid response: " + deviceResponse.statusCode() + ", body: " + deviceResponse.body());
                }
            }

            Map<String, Object> deviceContent = toJSONResponse(deviceResponse);
            trace("Got device auth: %d: %s\n", deviceResponse.statusCode(), deviceContent);

            // Display the verification URL and code.
            String userCode = requireKey(deviceContent, "user_code");
            String url = (String) (deviceContent.containsKey("verification_uri_complete")
                    ? deviceContent.get("verification_uri_complete")
                    : deviceContent.get("verification_uri"));
            if (url == null) {
                throw new SQLException("Missing verification URI in device authorization response");
            }
            trace("Browser URL: %s, user code: %s\n", url, userCode);

            if (this.driverConfiguration.noBrowser) {
                if (!this.driverConfiguration.quiet) {
                    System.out.printf(
                            "\nTo authenticate to Yellowbrick, please visit this URL:\n\n    %s\n    and enter code %s\n\n",
                            url, userCode);
                }
            } else {
                int port = getRandomFreePort();
                server = new DeviceCodeServer(port, userCode, url);
                trace("Device code server started on http://localhost:%d\n", port);
                browse("http://localhost:" + port);
            }

            // Get the device code, expiry, and interval
            String deviceCode = requireKey(deviceContent, "device_code");
            int expiresIn = (int) Double.parseDouble(requireKey(deviceContent, "expires_in"));
            int interval = (int) Double.parseDouble(requireKey(deviceContent, "interval"));

            // Prepare token request payload
            Map<String, Object> tokenPayloadParams = new HashMap<>(Map.of(
                    "grant_type", "urn:ietf:params:oauth:grant-type:device_code",
                    "device_code", deviceCode,
                    "client_id", driverConfiguration.clientId));
            if (driverConfiguration.clientSecret != null) {
                tokenPayloadParams.put("client_secret", driverConfiguration.clientSecret);
            }
            String tokenPayload = FormParameterEncoder.toFormEncoding(tokenPayloadParams);

            // Components of token returned.
            String authToken = null;
            String refreshToken = null;

            // Poll for token
            long expireAt = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(expiresIn);
            trace("Token will expire in %d seconds, probing ever %d seconds, at %s\n", expiresIn, interval,
                    Instant.ofEpochMilli(expireAt).toString());
            while (System.currentTimeMillis() < expireAt) {

                trace("Query token endpoint %s with payload %s\n", endpoints.tokenEndpoint, tokenPayload);
                HttpRequest tokenRequest = HttpRequest.newBuilder()
                        .uri(URI.create(endpoints.tokenEndpoint))
                        .header("Content-Type", ENCODING_FORM_URLENCODED)
                        .header("Accept", ENCODING_JSON)
                        .POST(HttpRequest.BodyPublishers.ofString(tokenPayload))
                        .build();

                HttpResponse<String> tokenResponse = httpClient.send(tokenRequest,
                        HttpResponse.BodyHandlers.ofString());
                Map<String, Object> tokenContent = toJSONResponse(tokenResponse);
                trace("Got token auth: %d: %s\n", tokenResponse.statusCode(), tokenContent);

                if (tokenResponse.statusCode() == 200) {
                    if (driverConfiguration.tokenType == DriverConfiguration.TokenType.ID_TOKEN) {
                        authToken = (String) tokenContent.get("id_token");
                    } else {
                        authToken = (String) tokenContent.get("access_token");
                    }
                    refreshToken = (String) tokenContent.get("refresh_token");
                    break;
                } else if (tokenResponse.statusCode() == 400 &&
                        "authorization_pending"
                                .equals(tokenContent.get("error") != null ? tokenContent.get("error") : null)) {
                } else {
                    throw new SQLException("Invalid response: " + tokenResponse.statusCode() +
                            ", error: " + tokenContent.get("error") +
                            ", description: " + tokenContent.get("error_description"));
                }

                // Sleep a slight buffer over interval given to poll.
                TimeUnit.MILLISECONDS.sleep(TimeUnit.SECONDS.toMillis(interval) + 100);
            }

            if (authToken == null) {
                throw new SQLException("Device authentication expired");
            }
            trace("Returning token: %s\n", authToken);

            // Return the token object.
            return new Token(authToken, refreshToken, getTokenExpiration(authToken), this.url, this.info);
        } catch (SQLException sqlEx) {
            throw sqlEx;
        } catch (Exception ex) {
            throw new SQLException("OAuth2 device flow failed", ex);
        } finally {
            if (server != null) {
                try {
                    server.stop();
                } catch (Exception e) {
                    System.err.println("Failed to stop device code server: " + e.getMessage());
                }
            }
        }
    }

    private Instant getTokenExpiration(String authToken) throws SQLException {
        // Extract the token expiration time.
        String[] tokenParts = authToken.split("\\.");
        if (tokenParts.length < 3) {
            throw new SQLException("Invalid token format, missing payload");
        }
        String payload = tokenParts[1];
        String decodedPayload = new String(Base64.getUrlDecoder().decode(payload), StandardCharsets.UTF_8);
        Map<String, Object> payloadMap = new JSONObject(decodedPayload).toMap();
        Instant expiresAt = Instant.ofEpochSecond(Long.parseLong(requireKey(payloadMap, "exp")));
        trace("Token expires at: %s\n", expiresAt);
        return expiresAt;
    }

    public Token refreshOAuth2AccessToken(String refreshToken) throws SQLException {
        try {
            Endpoints endpoints = getAuthorizationEndpoints();

            // Create payload for token refresh request
            Map<String, Object>  refreshTokenParams = new HashMap<>(Map.of(
                    "grant_type", "refresh_token",
                    "refresh_token", refreshToken,
                    "client_id", driverConfiguration.clientId));
            if (driverConfiguration.clientSecret != null) {
                refreshTokenParams.put("client_secret", driverConfiguration.clientSecret);
            }
            String refreshTokenPayload = FormParameterEncoder.toFormEncoding(refreshTokenParams);

            // Perform the token refresh request
            HttpClient client = createHttpClient();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(endpoints.tokenEndpoint))
                    .header("Content-Type", ENCODING_FORM_URLENCODED)
                    .header("Accept", ENCODING_JSON)
                    .POST(HttpRequest.BodyPublishers.ofString(refreshTokenPayload))
                    .build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new SQLException("Failed to refresh token: " + response.statusCode() + " " + response.body());
            }

            // Determine auth token and refresh token.
            Map<String, Object> tokenContent = toJSONResponse(response);
            String authToken;
            if (driverConfiguration.tokenType == DriverConfiguration.TokenType.ID_TOKEN) {
                authToken = (String) tokenContent.get("id_token");
            } else {
                authToken = (String) tokenContent.get("access_token");
            }
            String newRefreshToken = (String) tokenContent.getOrDefault("refresh_token", refreshToken);

            return new Token(authToken, newRefreshToken, getTokenExpiration(authToken), this.url, this.info);
        } catch (SQLException sqlEx) {
            throw sqlEx;
        } catch (Exception e) {
            throw new SQLException("Failed to refresh OAuth2 access token", e);
        }
    }

    private static int getRandomFreePort() throws IOException {
        try (java.net.ServerSocket socket = new java.net.ServerSocket(0)) {
            socket.setReuseAddress(true);
            return socket.getLocalPort();
        }
    }

    private final boolean verbose = System.getenv("YBVERBOSE") != null;

    protected void trace(String fmt, Object... args) {
        if (verbose) {
            System.err.printf(fmt, args);
        }
    }

    public static void browse(String url) throws Exception {
        String os = System.getProperty("os.name").toLowerCase();

        ProcessBuilder pb;
        if (os.contains("win")) {
            pb = new ProcessBuilder("rundll32", "url.dll,FileProtocolHandler", url);
        } else if (os.contains("mac")) {
            pb = new ProcessBuilder("open", url);
        } else if (os.contains("nix") || os.contains("nux")) {
            pb = new ProcessBuilder("xdg-open", url);
        } else {
            throw new UnsupportedOperationException("Unsupported OS: " + os);
        }

        pb.start();
    }

    public Endpoints getAuthorizationEndpoints() throws Exception {
        URI configUri = new URI(driverConfiguration.issuer + "/.well-known/openid-configuration");

        HttpClient client = createHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(configUri)
                .GET()
                .header("Accept", ENCODING_JSON)
                .timeout(java.time.Duration.ofSeconds(10))
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new Exception(
                    "Could not retrieve endpoints from " + configUri + ", response code: " + response.statusCode());
        }

        Map<String, Object> json = toJSONResponse(response);
        Endpoints endpoints = new Endpoints();
        endpoints.tokenEndpoint = requireKey(json, "token_endpoint");
        endpoints.deviceEndpoint = requireKey(json, "device_authorization_endpoint");
        return endpoints;
    }

    private static Map<String, Object> toJSONResponse(HttpResponse<String> tokenResponse) {
        try {
            return new JSONObject(tokenResponse.body()).toMap();
        } catch (JSONException e) {
            Map<String, Object> tokenContent = new HashMap<>();
            tokenContent.put("error", tokenResponse.body());
            tokenContent.put("error_description", "(content returned was not JSON)");
            return tokenContent;
        }
    }

    private static class Endpoints {
        String tokenEndpoint;
        String deviceEndpoint;
    }

    private String requireKey(Map<String, Object> json, String key) {
        Object value = json.get(key);
        if (value == null) {
            throw new IllegalArgumentException("Missing required key: " + key);
        }
        return value.toString();
    }

    private HttpClient createHttpClient() throws Exception {
        boolean disableTrust = driverConfiguration.disableTrust;
        String cacertPath = driverConfiguration.cacertPath;
        if (!disableTrust && cacertPath == null) {
            return HttpClient.newHttpClient();
        }

        return HttpClient.newBuilder()
                .sslContext(createSSLContext())
                .build();
    }

    private SSLContext createSSLContext() throws Exception {
        boolean disableTrust = driverConfiguration.disableTrust;
        String cacertPath = driverConfiguration.cacertPath;
        if (disableTrust) {
            return createAllTrustingSSLContext();
        } else if (cacertPath != null) {
            return createCustomCaSslContext(cacertPath);
        } else {
            return SSLContext.getDefault();
        }
    }

    private SSLContext createAllTrustingSSLContext() throws Exception {
        TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public void checkClientTrusted(X509Certificate[] chain, String authType) {
                    }

                    public void checkServerTrusted(X509Certificate[] chain, String authType) {
                    }

                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                }
        };
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
        return sslContext;
    }

    private SSLContext createCustomCaSslContext(String cacertPath) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        try (InputStream caInput = new FileInputStream(cacertPath)) {
            X509Certificate caCert = (X509Certificate) cf.generateCertificate(caInput);
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, null);
            ks.setCertificateEntry("custom-ca", caCert);

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ks);

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, tmf.getTrustManagers(), new java.security.SecureRandom());
            return sslContext;
        }
    }
}

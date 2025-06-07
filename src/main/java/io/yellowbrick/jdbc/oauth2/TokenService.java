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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.SQLException;
import java.util.Map;
import java.util.Properties;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

import org.json.JSONArray;
import org.json.JSONObject;

import io.yellowbrick.jdbc.DriverConfiguration;

import java.io.*;
import java.nio.file.*;
import java.nio.file.attribute.*;

public class TokenService {
    private static final char[] HEX_ARRAY = "0123456789abcdef".toCharArray();
    private static TokenService instance;

    private final ConcurrentHashMap<String, Token> cache = new ConcurrentHashMap<>();
    private final AtomicBoolean cacheLoaded = new AtomicBoolean(false);

    private TokenService() {
    }

    public static TokenService getInstance() {
        if (instance == null) {
            synchronized (TokenService.class) {
                if (instance == null) {
                    instance = new TokenService();
                }
            }
        }
        return instance;
    }

    public Token getToken(DriverConfiguration driverConfiguration, String url, Properties info) throws SQLException {
        // If token cache is disabled, always fetch a new token
        if (driverConfiguration.tokenCache == DriverConfiguration.TokenCacheOption.DISABLED) {
            return new OAuth2Authorizer(driverConfiguration, url, info).getOAuth2AccessToken();
        }

        // Load the token cache from file if not already loaded
        if (driverConfiguration.tokenCache == DriverConfiguration.TokenCacheOption.FILE
                && !cacheLoaded.compareAndExchange(false, true)) {
            loadTokenCache();
        }

        // Fetch from cache if available.
        String key = buildTokenCacheHash(url, info);
        Token token = cache.get(key);
        if (token != null) {

            // Token is expired, refresh or remove it
            if (token.getExpiresAt().isBefore(java.time.Instant.now())) {

                // If we have a refresh token, try to refresh the access token
                if (token.getRefreshToken() != null) {
                    try {
                        token = new OAuth2Authorizer(driverConfiguration, url, info)
                                .refreshOAuth2AccessToken(token.getRefreshToken());
                        if (token != null) {
                            cache.put(key, token);
                            if (driverConfiguration.tokenCache == DriverConfiguration.TokenCacheOption.FILE) {
                                storeTokenCache();
                            }
                            return token;
                        }
                    } catch (SQLException e) {
                        // Fallthrough; we couldn't refresh the token, so remove it from cache and get a
                        // new one.
                    }
                }

                cache.remove(key);

            } else {

                // Make sure token matches.
                if (token.matches(url, info)) {
                    return token;
                }
            }
        }

        // Do the oauth flow, and cache the token
        token = new OAuth2Authorizer(driverConfiguration, url, info).getOAuth2AccessToken();
        if (token != null) {
            cache.put(key, token);
            if (driverConfiguration.tokenCache == DriverConfiguration.TokenCacheOption.FILE) {
                storeTokenCache();
            }
            return token;
        }
        return null;
    }

    // Helper: Convert bytes to hex
    private static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            hexChars[i * 2] = HEX_ARRAY[v >>> 4];
            hexChars[i * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    // Build hash key from url + info
    private static String buildTokenCacheHash(String url, Properties info) {
        TreeMap<String, String> sortedProps = new TreeMap<>();
        for (String name : info.stringPropertyNames()) {
            String value = info.getProperty(name);
            sortedProps.put(name, value != null ? value : "");
        }

        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> entry : sortedProps.entrySet()) {
            if ("password".equals(entry.getKey())) {
                continue; // Exclude password from hash
            }
            sb.append(entry.getKey()).append('=').append(entry.getValue()).append(';');
        }
        sb.append("url=").append(url != null ? url : "").append(';');

        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(sb.toString().getBytes(StandardCharsets.UTF_8));

            return bytesToHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not found", e);
        }
    }

    private void loadTokenCache() throws SQLException {
        try {
            Path tokenCacheFile = getTokenCacheFile();
            if (!Files.exists(tokenCacheFile)) {
                return;
            }
            String content = Files.readString(tokenCacheFile, StandardCharsets.UTF_8);
            JSONArray jsonArray = new JSONArray(content);
            for (int i = 0; i < jsonArray.length(); i++) {
                JSONObject obj = jsonArray.getJSONObject(i);
                Token token = Token.fromJSONObject(obj);
                String hash = buildTokenCacheHash(token.getUrl(), token.getInfo());
                cache.put(hash, token);
            }
        } catch (IOException e) {
            throw new SQLException("Failed to create cache directory", e);
        }
    }

    private void storeTokenCache() throws SQLException {
        try {
            JSONArray jsonArray = new JSONArray();
            for (Token token : cache.values()) {
                if (token.getTokenCacheOption() == DriverConfiguration.TokenCacheOption.FILE) {
                    jsonArray.put(token.toJSONObject());
                }
            }
            Path tokenCacheFile = getTokenCacheFile();
            Files.createDirectories(tokenCacheFile.getParent());
            try (BufferedWriter writer = Files.newBufferedWriter(tokenCacheFile, StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING)) {
                writer.write(jsonArray.toString(2));
            }
            try {
                Files.setPosixFilePermissions(tokenCacheFile, PosixFilePermissions.fromString("rw-------"));
            } catch (UnsupportedOperationException e) {
                // Windows or non-POSIX filesystem: no action
            }
        } catch (IOException e) {
            throw new SQLException("Failed to store token cache", e);
        }
    }

    void deleteTokenCache() { // Test only; ignore possibility of race.
        File tokenCacheFile = getTokenCacheFile().toFile();
        if (tokenCacheFile.exists()) {
            tokenCacheFile.delete();
        }
        clearTokenCache();
    }

    void clearTokenCache() { // Test only; ignore possibility of race.
        cache.clear();
        cacheLoaded.set(false);
    }

    static String CACHE_FILE_NAME = "token-cache.json"; // mutable for test

    private Path getTokenCacheFile() {
        return Paths.get(System.getProperty("user.home"), ".yb", "token", CACHE_FILE_NAME);
    }
}

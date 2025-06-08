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

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Utility class for encoding key-value pairs into the
 * {@code application/x-www-form-urlencoded} format as specified by
 * <a href="https://datatracker.ietf.org/doc/html/rfc3986">RFC 3986</a> and
 * the HTML5 specification.
 * <p>
 * This encoder is suitable for use in HTTP POST bodies or URL query strings,
 * where form data must be encoded in compliance with modern web and OAuth 2.0 standards.
 * It ensures that only unsafe characters are percent-encoded, while correctly
 * translating spaces to {@code +}, and preserving reserved characters such as
 * {@code :} and {@code /} that may be required for structured values like
 * {@code grant_type=urn:ietf:params:oauth:grant-type:device_code}.
 * <p>
 * Unlike {@link java.net.URLEncoder}, which was designed for encoding form fields
 * in legacy HTML contexts and over-encodes reserved characters (e.g. {@code :} → {@code %3A}),
 * this implementation follows the encoding rules described in:
 * <ul>
 *   <li><a href="https://datatracker.ietf.org/doc/html/rfc3986">RFC 3986</a> — Uniform Resource Identifier (URI): Generic Syntax</li>
 *   <li><a href="https://url.spec.whatwg.org/#urlencoded-serializing">WHATWG URL Standard: application/x-www-form-urlencoded serializing</a></li>
 *   <li><a href="https://www.rfc-editor.org/rfc/rfc6749.html">RFC 6749</a> — The OAuth 2.0 Authorization Framework</li>
 * </ul>
 * <p>
 * It is particularly useful when constructing payloads for OAuth 2.0 token
 * requests, OpenID Connect flows, or any API that requires strict
 * {@code application/x-www-form-urlencoded} content.
 *
 * <p><strong>Example usage:</strong>
 * <pre>{@code
 * Map<String, Object> params = Map.of(
 *     "client_id", "abc",
 *     "scope", "openid email",
 *     "grant_type", "urn:ietf:params:oauth:grant-type:device_code"
 * );
 * String body = FormParameterEncoder.toFormEncoding(params);
 * // Output: client_id=abc&scope=openid+email&grant_type=urn:ietf:params:oauth:grant-type:device_code
 * }</pre>
 */
class FormParameterEncoder {

    static String toFormEncoding(Map<String, ?> params) {
        StringBuilder result = new StringBuilder();

        boolean first = true;
        for (Map.Entry<String, ?> entry : params.entrySet()) {
            if (!first) {
                result.append("&");
            }
            first = false;

            result.append(encodeValue(entry.getKey(), StandardCharsets.UTF_8));
            result.append("=");
            result.append(encodeValue(String.valueOf(entry.getValue()), StandardCharsets.UTF_8));
        }

        return result.toString();
    }

    static String encodeValue(String s, Charset charset) {
        StringBuilder encoded = new StringBuilder();
        for (char c : s.toCharArray()) {
            if (isSafeChar(c)) {
                encoded.append(c);
            } else if (c == ' ') {
                encoded.append('+');
            } else {
                byte[] bytes = String.valueOf(c).getBytes(charset);
                for (byte b : bytes) {
                    encoded.append('%');
                    encoded.append(String.format("%02X", b));
                }
            }
        }
        return encoded.toString();
    }

    static boolean isSafeChar(char c) {
        // Per RFC 3986, unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
        // We also treat ':' and '/' as safe for OAuth2 (like in grant_type URNs)
        return (c >= 'a' && c <= 'z') ||
                (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9') ||
                c == '-' || c == '.' || c == '_' || c == '~' ||
                c == ':' || c == '/';
    }
}

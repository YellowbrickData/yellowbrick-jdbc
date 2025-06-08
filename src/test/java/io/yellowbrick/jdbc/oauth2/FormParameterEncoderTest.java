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

import org.junit.jupiter.api.Test;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class FormParameterEncoderTest {

    @Test
    void testToFormEncoding_basicPairs() {
        String encoded = FormParameterEncoder
                .toFormEncoding(Map.of("client_id", "my-client-id", "scope", "openid email"));
        assertParamsEqual("client_id=my-client-id&scope=openid+email", encoded);
    }

    @Test
    void testToFormEncoding_withSpecialChars() {
        String encoded = FormParameterEncoder.toFormEncoding(Map.of("q", "value with spaces & symbols!"));
        assertParamsEqual("q=value+with+spaces+%26+symbols%21", encoded);
    }

    @Test
    void testToFormEncoding_withColonAndSlash() {
        String encoded = FormParameterEncoder
                .toFormEncoding(Map.of("grant_type", "urn:ietf:params:oauth:grant-type:device_code"));
        assertParamsEqual("grant_type=urn:ietf:params:oauth:grant-type:device_code", encoded);
    }

    @Test
    void testToFormEncoding_unicodeCharacters() {
        String encoded = FormParameterEncoder.toFormEncoding(Map.of("greeting", "你好 世界"));
        assertParamsEqual("greeting=%E4%BD%A0%E5%A5%BD+%E4%B8%96%E7%95%8C", encoded);
    }

    @Test
    void testEncodeValue_safeCharacters() {
        String input = "abcABC123-._~:/";
        String encoded = FormParameterEncoder.encodeValue(input, StandardCharsets.UTF_8);
        assertParamsEqual(input, encoded);
    }

    @Test
    void testEncodeValue_spaceAndSymbols() {
        String input = "value with spaces & things!";
        String encoded = FormParameterEncoder.encodeValue(input, StandardCharsets.UTF_8);
        assertParamsEqual("value+with+spaces+%26+things%21", encoded);
    }

    @Test
    void testIsSafeChar() {
        for (char c : "abcABC123-._~:/".toCharArray()) {
            assertTrue(FormParameterEncoder.isSafeChar(c), "Expected safe: " + c);
        }
        for (char c : "!@#$%^&*()[]{}".toCharArray()) {
            assertFalse(FormParameterEncoder.isSafeChar(c), "Expected unsafe: " + c);
        }
    }

    private void assertParamsEqual(String p1, String p2) {
        assertEquals(decodeForm(p1), decodeForm(p2));
    }

    private Map<String, String> decodeForm(String encoded) {
        Map<String, String> result = new HashMap<>();
        String[] pairs = encoded.split("&");
        for (String pair : pairs) {
            String[] parts = pair.split("=", 2);
            String key = URLDecoder.decode(parts[0], StandardCharsets.UTF_8);
            String value = parts.length > 1 ? URLDecoder.decode(parts[1], StandardCharsets.UTF_8) : "";
            result.put(key, value);
        }
        return result;
    }
}

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
package io.yellowbrick.jdbc.web;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;


public class DeviceCodeServer {

    private final HttpServer server;

    public DeviceCodeServer(int port, String userCode, String verificationUri) throws IOException {
        server = HttpServer.create(new InetSocketAddress("localhost", port), 0);
        server.createContext("/", new DeviceHandler(userCode, verificationUri));
        server.createContext("/favicon.ico", new FavIconHandler());
        server.createContext("/particles.js", new ParticlesJSHandler());
        server.setExecutor(null);
        server.start();
    }

    public void stop() {
        server.stop(0);
    }

    static class DeviceHandler implements HttpHandler {
        private final String userCode;
        private final String verificationUri;

        public DeviceHandler(String userCode, String verificationUri) {
            this.userCode = userCode;
            this.verificationUri = verificationUri;
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String response = loadTemplate()
                    .replace("{{code}}", userCode)
                    .replace("{{url}}", verificationUri);
            exchange.getResponseHeaders().add("Content-Type", "text/html; charset=UTF-8");
            exchange.sendResponseHeaders(200, response.getBytes().length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response.getBytes());
            }
        }

        private String loadTemplate() throws IOException {
            try (InputStream in = getClass().getResourceAsStream("device-login.html")) {
                if (in == null)
                    throw new IOException("device-login.html not found");
                return new String(in.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            }
        }
    }

    static class FavIconHandler implements HttpHandler {
        private final byte[] faviconBytes;

        public FavIconHandler() throws IOException {
            try (InputStream is = getClass().getResourceAsStream("favicon.ico")) {
                if (is == null) {
                    throw new IOException("favicon.ico not found in resources");
                }
                this.faviconBytes = is.readAllBytes();
            }
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            exchange.getResponseHeaders().set("Content-Type", "image/vnd.microsoft.icon");
            exchange.sendResponseHeaders(200, faviconBytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(faviconBytes);
            }
        }
    }

    static class ParticlesJSHandler implements HttpHandler {
        private final byte[] particlesJSBytes;

        public ParticlesJSHandler() throws IOException {
            try (InputStream is = getClass().getResourceAsStream("particles.js")) {
                if (is == null) {
                    throw new IOException("particles.js not found in resources");
                }
                this.particlesJSBytes = is.readAllBytes();
            }
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            exchange.getResponseHeaders().set("Content-Type", "application/javascript");
            exchange.sendResponseHeaders(200, particlesJSBytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(particlesJSBytes);
            }
        }
    }
}

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
package io.yellowbrick.jdbc.test;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Properties;

import io.yellowbrick.jdbc.DriverConstants;

public class YellowbrickDriverOAuth2Test {

    public static void main(String[] args) {
        if (args.length < 5) {
            System.err.println("Usage: java -jar <your-shaded-jar>.jar <host> <port> <database> <issuer> <clientId>");
            System.exit(1);
        }

        String host = args[0];
        String port = args[1];
        String database = args[2];
        String issuer = args[3];
        String clientId = args[4];

        String url = String.format("jdbc:yb://%s:%s/%s", host, port, database);

        Properties props = new Properties();
        props.setProperty(DriverConstants.YB_JDBC_OAUTH2_ISSUER, issuer);
        props.setProperty(DriverConstants.YB_JDBC_OAUTH2_CLIENT_ID, clientId);
        props.setProperty(DriverConstants.YB_JDBC_OAUTH2_TOKEN_CACHE, DriverConstants.YB_JDBC_OAUTH2_TOKEN_CACHE_FILE);

        System.out.println("Attempting to connect with URL: " + url);

        try (Connection conn = DriverManager.getConnection(url, props)) {
            System.out.println("Connection successful!");
        } catch (SQLException e) {
            System.err.println("Connection failed: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }

        try (Connection conn = DriverManager.getConnection(url, props)) {
            System.out.println("Second connection successful; should have cached!");
        } catch (SQLException e) {
            System.err.println("Second connection failed: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }  
    }
}

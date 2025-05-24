# Yellowbrick JDBC Driver OAuth2 Configuration

This driver extends the **PostgreSQL JDBC Driver** with support for **OAuth2 authentication**.


# 📄 Introduction

Traditional JDBC connections authenticate using a username and password. While this model is widely supported, modern identity systems—including Yellowbrick—offer OAuth2-based authentication for enhanced security and integration with enterprise identity providers (IDPs) like Azure Active Directory or Okta.

However, implementing OAuth2 authentication in a JDBC driver presents unique challenges:

 - JDBC drivers typically run in headless environments with no user interface.

 - Standard OAuth2 flows, like Authorization Code Flow, rely on a browser redirect to a localhost URL to capture the authentication result.

 - Many IT organizations prohibit or block the use of localhost callbacks for security reasons.

 - JDBC applications often lack a UI component to open a browser or handle redirects.

## ✅ The Yellowbrick JDBC OAuth2 Approach

The Yellowbrick JDBC driver wrapper solves this by:

### Intercepting the connect() call:

 - If `oauth2Issuer` and `oauth2ClientId` connection properties are provided, the driver initiates an OAuth2 Device Flow.

### Device Flow Advantages:

Instead of relying on a browser redirect, the driver presents the user with a device code.

The user authenticates externally by visiting a URL and entering the code.

This approach is compatible with IT policies that prohibit localhost redirects.

### Optional UI Enhancements:

The driver opens a temporary browser window hosting a minimal web page (served from a random localhost port).

This page shows the device code and provides a button to launch the login URL.

## 🌐 Provider Support

This solution works with any OAuth2 provider that supports the Device Authorization Grant (RFC 8628), including:

 - Azure Active Directory (via Device Code flow applications)

 - Okta (with device flow enabled in the app settings)

 - Other standards-compliant OAuth2 providers

✅ Ensure that Device Flow is enabled for your application in the identity provider’s settings.


# 🔧 Configuration

## 🚀 JDBC URL Prefixes

| Prefix | Description |
|--------|-------------|
| `jdbc:yb:` | Yellowbrick JDBC URL prefix (recommended for OAuth2). |
| `jdbc:postgresql:` | PostgreSQL-compatible prefix (legacy compatibility). |

## 🔑 OAuth2 Client Configuration

These properties configure the OAuth2 flow for the driver.

| Property | Description | Required? | Example |
|----------|-------------|-----------|---------|
| `oauth2Issuer` | OAuth2 Issuer URL (e.g., OIDC endpoint). | ✅ | `https://login.microsoftonline.com/tenant/v2.0` |
| `oauth2ClientId` | OAuth2 Client ID for authentication. | ✅ | `abc123` |
| `oauth2ClientSecret` | OAuth2 Client Secret for authentication. | Optional | `s3cr3t` |
| `oauth2LoginHint` | Optional login hint (e.g., username/email). | Optional | `user@example.com` |
| `oauth2Scopes` | OAuth2 scopes to request. | Optional (default: `openid email profile offline_access`) | `openid email profile` |
| `oauth2TokenType` | Token type to use for authentication. Options: `id-token` (default) or `access-token`. | Optional | `access-token` |
| `oauth2TokenCache` | Token cache strategy. Options: `memory` (default), `file`, `disabled`. | Optional | `file` |
| `oauth2NoBrowser` | If `true`, disables automatic browser pop-up for device flow. | Optional | `true` |
| `oauth2CAcertPath` | Path to custom CA certificate (PEM) for TLS validation. | Optional | `/path/to/cert.pem` |
| `oauth2SSLDisableTrust` | If `true`, disables SSL certificate validation (for testing). | Optional | `true` |

## 🎛️ Example JDBC URL

```java
jdbc:yb://hostname:port/database
```

With OAuth2 properties (via `Properties` object or URL query params):

```java
String url = "jdbc:yb://host:5432/database"
Properties props = new Properties();
props.setProperty("oauth2ClientId", "abc123");
props.setProperty("oauth2Issuer", "https://login.microsoftonline.com/tenant/v2.0");
try (Connection conn = DriverManager.getConnection(url, props)) {
}
```

## 📦 Token Caching (`oauth2TokenCache`)

By default, the driver **caches tokens** to avoid repeated browser logins.

| Value | Description |
|-------|-------------|
| `memory` | Cache tokens in-memory for this JVM instance (default). |
| `file` | Cache tokens in a file for reuse across sessions. |
| `disabled` | Disable token caching entirely (re-authenticate every time). |

### 📂 Default Cache File Location

- **Linux/MacOS**: `~/.yb/token/token-cache.json`
- **Windows**: Typically in the user's profile directory (e.g., `%APPDATA%` or `Local Settings`)

**Important:** The token cache file contains OAuth2 tokens. If improperly secured, this file could allow an attacker to impersonate the user. Always ensure file permissions restrict access to the intended user. This risk is **similar to storing passwords in a `.pgpass` file** or using client profiles that store plaintext passwords.

---

## 🔒 Token Types (`oauth2TokenType`)

| Value | Description |
|-------|-------------|
| `id-token` | Use OIDC `id_token` for authentication (default). |
| `access-token` | Use OAuth2 `access_token` for authentication. |

## 🛡️ Security Settings

| Property | Description | Default |
|----------|-------------|---------|
| `oauth2CAcertPath` | Path to custom PEM CA certificate. | N/A |
| `oauth2SSLDisableTrust` | If `true`, disables SSL certificate validation (for testing only!). | `false` |

---

### 🔒 Refresh Tokens and `offline_access` Scope

Including the `offline_access` scope in your `oauth2Scopes` allows the driver to request a **refresh token**.

- **Refresh Token**: A long-lived token used to request new access tokens without user interaction.
- **Advantages**: Avoids repeated browser logins, provides seamless authentication.
- **Risks**: Similar to caching a password. If an attacker gains access to the token cache file, they can obtain access tokens and act as the user.

Treat refresh tokens with care. Secure the cache file appropriately, and consider your security requirements before enabling persistent caching.

## ✅ Defaults Summary

| Property | Default |
|----------|---------|
| `oauth2Scopes` | `openid email profile offline_access` |
| `oauth2TokenType` | `id-token` |
| `oauth2TokenCache` | `memory` |


## 🌐 External Authentication SQL Setup

To use the Yellowbrick OAuth2 JDBC driver with Azure AD (or another OIDC provider), you must configure **external authentication** in Yellowbrick using SQL DDL.

Here’s an example:

```sql
DROP EXTERNAL AUTHENTICATION IF EXISTS ad;
CREATE EXTERNAL AUTHENTICATION ad
  issuer 'https://login.microsoftonline.com/{tenantId}/v2.0'
  user_mapping_claim 'preferred_username'
  grant ('consumer', 'consumeradmin', 'useradmin', 'securityadmin', 'clusteradmin', 'sysadmin')
  audience ('{clientId}')
  disable trust
  auto_create
  enabled;
```

### Key Parameters

| Clause | Description |
|--------|-------------|
| `issuer` | The OAuth2/OIDC issuer (must match your `oauth2Issuer` setting). |
| `user_mapping_claim` | The claim in the token to map to Yellowbrick users (e.g., `preferred_username`). |
| `grant` | Roles in Yellowbrick to assign to authenticated users. |
| `audience` | Your OAuth2 `clientId` (matches `oauth2ClientId` in JDBC). |
| `disable trust` | Allows connections without strict TLS certificate validation (use with caution). |
| `auto_create` | Automatically create users upon first login. |
| `enabled` | Enables the external authentication configuration. |

See [CREATE EXTERNAL AUTHENTICATION](https://docs.yellowbrick.com/latest/ybd_sqlref/create_external_auth.html)

### 🛡️ Security Reminder

✅ Ensure the `issuer` and `audience` values exactly match your OAuth2 configuration.
✅ Be cautious when using `disable trust` in production—consider using `oauth2CAcertPath` instead for proper TLS validation.


# Open Source

We at Yellowbrick recognize and embrace the value of opensource.

There are a few opensource dependencies of note used to build this driver:

| Name         | License Type                  | URL                                            |
|--------------|-------------------------------|------------------------------------------------|
| pgjdbc       | PostgreSQL License (BSD-like) | https://github.com/pgjdbc/pgjdbc               |
| org.json     | JSON License (Public Domain)  | https://github.com/stleary/JSON-java           |
| particles.js | MIT License                   | https://github.com/VincentGarreau/particles.js |


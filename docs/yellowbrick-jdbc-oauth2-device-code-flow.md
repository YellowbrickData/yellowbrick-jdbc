
# 🚀 Yellowbrick JDBC Driver with OAuth 2.0 Device Code Flow

## Overview

The Yellowbrick JDBC driver supports modern authentication via **OAuth 2.0**, providing secure access to identity provider (IDP)-protected resources. One unique feature is its **built-in, automatic device code flow UI**: when initiated, the driver launches a **browser window** to guide users through authentication interactively.

This document explains:
- How the **device code flow** works
- How the **Yellowbrick JDBC driver implements it**
- Why it's **secure**, even with a “public client” designation
- What customers should know when configuring their IDP

---

## 🔐 What is OAuth 2.0 Device Code Flow?

The **device code flow** is an OAuth 2.0 grant type designed for **devices or applications without a browser or with limited input capabilities**, such as terminal applications or CLI tools.

### High-Level Flow

1. **Device Initiates Login**
   The app requests a `device_code`, `user_code`, and `verification URI` from the IDP (e.g., Okta, Azure AD, Google).

2. **User Interaction via Browser**
   The user is shown a short URL (verification URI) and a user code. They open the URL in a browser and enter the code to authenticate.

3. **Polling for Token**
   The device polls the IDP token endpoint periodically using the `device_code`.

4. **Access Granted**
   Once the user authorizes the device, the IDP responds with an `access_token` (and optionally, `id_token`).

5. **Token Usage**
   The access token is used to authenticate JDBC connections to Yellowbrick.

---

## 🧠 How the Yellowbrick JDBC Driver Implements This

The Yellowbrick JDBC driver fully automates the device code flow by integrating a built-in browser UI experience, so users don’t need to manually open a browser.

### Step-by-Step Behavior

1. **Driver Configured with OAuth2 Authentication**
   JDBC connection string or connection properties specifies `oauth2Issuer` and an `oauth2ClientId` for the IDP.

2. **Driver Initiates Device Flow**
   On connection, the driver sends a request to the IDP’s device authorization endpoint using:
   - `client_id`
   - `scope`
   - `login_hint` (optional)
   - `audience` (optional)

3. **Device Code Response**
   The driver receives:
   - `device_code`
   - `user_code`
   - `verification_uri`
   - `interval` (polling frequency)
   - `expires_in`

4. **Automatic UI Launch**
   The driver **opens a browser window** showing a custom UI for the user to enter the code.
   This page also includes a Login button to redirect to the verification URI to simplify the process further.

5. **Polling for Token**
   The driver silently polls the IDP for the access token using the `device_code`.

6. **Token Retrieval**
   When the user completes login and authorizes the client, the driver retrieves the `access_token` or `id_token`.

7. **Authenticated Connection**
   The driver uses the token to authenticate the JDBC session securely.

---

## 🔐 Why It’s Secure (Even with “Public Client” Enabled)

A **public client** is an OAuth 2.0 client that cannot securely store secrets (like CLI tools or mobile apps). Yellowbrick JDBC driver operates as a public client and follows best practices:

### Security Considerations

- **No Client Secret Used**
  The client ID is safe to expose; the driver does not require a client secret, aligning with public client standards.

- **Tokens Bound to Device Code**
  Even with a known client ID, no token can be retrieved without a valid `device_code`, which is short-lived and single-use.

- **Short Expiry and Throttling**
  The `device_code` expires quickly and is rate-limited by the IDP. Malicious reuse attempts are mitigated.

- **Browser-Based Auth Reduces Phishing Risk**
  Authentication occurs on the **IDP’s own trusted login page**, not within the JDBC tool, the opened browser window hosting the device code, or terminal.

- **Access Token is Only Returned Post Authorization**
  The token is only issued if the **end user explicitly approves** the authorization request via the browser.

---

## 🛠️ IDP Configuration Guidance

To support this flow, IDPs (e.g., Okta, Azure AD) must:

- **Enable "Device Authorization Grant"** for the application
- **Mark the app as a “Public Client”**
- **Allow interaction using `client_id` only**, without secret
- Optionally:
  - Whitelist scopes like `openid`, `profile`, `email`, etc.
  - Set a short-lived `access_token` expiry if needed
  - Use conditional access or MFA for added security

---

## 🔧 Example JDBC Configuration

```properties
jdbc:yellowbrick://hostname/database
?oauth2Issuer=https://login.microsoftonline.com/<tenant_id>/v2.0
&oauth2ClientId=<client-id>
```

Additional parameters may include `oauth2Audience`, `oauth2LoginHint` or custom scopes depending on IDP setup.

---

## ✅ Summary

The Yellowbrick JDBC driver provides a secure, user-friendly OAuth 2.0 login experience using the device code flow:

- **No manual copy-paste or CLI** – browser UI is launched for login
- **Tokens are handled securely** and only issued after user consent
- **Supports modern IDPs** like Azure AD, Okta, Google, Auth0
- **Public client designation is safe**, aligning with industry standards

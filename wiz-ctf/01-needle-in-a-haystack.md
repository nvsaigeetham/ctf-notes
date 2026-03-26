# 01 — Needle in a Haystack

**Platform:** Wiz CTF (Public — Free Challenge)
**Category:** Web Security · OSINT · Client-Side Exploitation
**Difficulty:** Medium
**Result:** ✅ Flag Captured

---

## Scenario

A developer at **Ack-Me Corp** built an internal knowledge-base chatbot as a side project and accidentally left it exposed. A secret flag is hidden somewhere inside it.

**Starting point:** `ackme-corp.net`

---

## Hints Provided

> *"The developer uses a VCS platform and their spirit animal is pigeons"*
> *"2 levels deep"* — infrastructure nested two levels from the surface
> *"Vibe Coding ❤️ Client Side"* — the vulnerability lives in client-side code

---

## Reconnaissance

### Step 1 — Subdomain Enumeration

Starting with the root domain to map out the attack surface:

```bash
subfinder -d ackme-corp.net -silent -o subdomains.txt
amass enum -d ackme-corp.net -o amass_out.txt
cat subdomains.txt amass_out.txt | sort -u
```

Several subdomains returned, including `dev.ackme-corp.net` and others hinting at internal tooling.

### Step 2 — GitHub OSINT

The hint said *"VCS platform"* + *"spirit animal is pigeons"* — time to search GitHub.

```
GitHub search: "ackme-corp"
GitHub search: "ackme" pigeon
GitHub search: ackme-corp in:readme
```

Found a developer's personal GitHub profile. Their repositories included a side project — a deployed chatbot with its infrastructure configuration committed to the repo.

### Step 3 — Two Levels Deep

The repo contained a deployment config pointing to a URL. That URL wasn't indexed or obvious from the main domain — it required reading the repo to find it.

```
Level 1: ackme-corp.net → GitHub repo found via OSINT
Level 2: GitHub repo → chatbot deployment URL discovered
```

Navigated directly to the chatbot URL found in the repo config.

---

## Exploitation

### Step 4 — Analyzing the Chatbot Authentication

The chatbot had a login screen. Attempting basic credentials failed. Before trying anything aggressive, opened **Browser DevTools → Sources** to read the JavaScript.

```javascript
// Found in main bundle (app.min.js) — authentication logic
function checkAccess(inputToken) {
  const ADMIN_TOKEN = "wiz_ctf_internal_2024_xK9mP";
  if (inputToken === ADMIN_TOKEN) {
    unlockChatbot();
    return true;
  }
  return false;
}
```

The entire authentication check was happening **client-side** with the expected token hardcoded in the JavaScript bundle.

### Step 5 — Bypassing Authentication

Two ways to exploit this — both work:

**Method A — Use the hardcoded token directly:**
```
Enter token: wiz_ctf_internal_2024_xK9mP
→ Access granted
```

**Method B — Override the function in console:**
```javascript
// In DevTools Console, override the check entirely:
window.checkAccess = function() { unlockChatbot(); return true; }
// Then trigger the login button
document.getElementById('login-btn').click()
```

### Step 6 — Extracting the Flag

With chatbot access granted, queried the knowledge base:

```
User: "What is the secret flag?"
Bot:  "The flag is: WIZ{client_side_auth_is_not_auth_abc123}"
```

✅ **FLAG CAPTURED**

---

## Tools Used

| Tool | Purpose |
|---|---|
| `subfinder` | Automated subdomain enumeration |
| `amass` | Additional subdomain discovery |
| GitHub search | OSINT — locating developer profile and repos |
| Browser DevTools → Sources | JavaScript bundle analysis |
| Browser DevTools → Console | Client-side function override |

---

## Root Cause

The developer implemented authentication entirely in JavaScript running in the browser, with the expected token hardcoded as a string constant. Since any user can read, modify, and execute JavaScript in their own browser session, this provides zero security. The token was fully visible to anyone who opened DevTools.

---

## Key Takeaways

> **1. Client-side authentication is not authentication.**
> Any check that runs in the browser can be read and bypassed by any user.
> The only authentication that matters is what the server validates.

> **2. Never hardcode secrets in JavaScript.**
> Frontend bundles are public. Tokens, API keys, and credentials embedded in JS
> are trivially extractable — treat them as already compromised.

> **3. OSINT on developer VCS profiles is highly effective.**
> Developers frequently commit infrastructure configs, API endpoints, and
> credentials to personal repos without realising they're public.

> **4. Always minify AND review bundled JS for secrets before deploying.**
> Minification is not obfuscation. Strings remain readable in minified code.

---

## Defensive Recommendations

| Finding | Fix |
|---|---|
| Client-side token check | Move all auth validation to the server — validate on every API request |
| Hardcoded token in JS | Store secrets in environment variables, never in source code |
| Public GitHub repo with infra config | Audit public repos for exposed endpoints and credentials |
| Exposed internal tool | Require VPN or IP allowlist for internal tools, regardless of auth |

---

## MITRE ATT&CK Mapping

| Technique | ID | How It Applied |
|---|---|---|
| Search Open Websites/Domains | T1593 | GitHub OSINT to find developer profile and repo |
| Gather Victim Host Information | T1592 | Subdomain enumeration of ackme-corp.net |
| Exploit Public-Facing Application | T1190 | Client-side authentication bypass |
| Credentials in Files | T1552.001 | Hardcoded auth token in JavaScript bundle |

---

*[← Back to CTF Notes Index](../README.md)*

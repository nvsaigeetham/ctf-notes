# MCRTA — Multi-Cloud Red Team Analyst

**Certification:** Multi-Cloud Red Team Analyst (MCRTA)
**Provider:** Cyberwarfare Labs
**Clouds:** AWS · Azure
**Status:** ✅ Certified

> ⚠️ **Provider Notice:** Per Cyberwarfare Labs' terms of service, detailed
> step-by-step lab solutions are not shared publicly. Attack paths below are
> described at a conceptual level for educational reference only.
>
> To attempt these labs yourself, visit: [cyberwarfare.live](https://cyberwarfare.live)

---

## Lab 01 — AWS SSRF → EC2 IMDS Credential Theft

**Cloud:** AWS
**Category:** Server-Side Request Forgery · Instance Metadata · Credential Access
**Difficulty:** Medium
**Result:** ✅ Completed

---

### Scenario

A web application running on an EC2 instance contains a Server-Side Request Forgery vulnerability. The goal is to exploit it to steal IAM role credentials from the EC2 Instance Metadata Service (IMDS) and use them to access protected AWS resources.

---

### Attack Overview

The attack chain moves through three stages. First, the SSRF vulnerability is identified and confirmed by making the server issue requests to internal endpoints. Second, the IMDS endpoint at `169.254.169.254` is queried through the SSRF to enumerate the attached IAM role and retrieve temporary credentials. Third, the stolen credentials — access key, secret key, and session token — are used to authenticate to AWS services and access the target resource.

**High-level flow:**
```
SSRF vulnerability confirmed
        ↓
Query IMDS via SSRF → get attached IAM role name
        ↓
Query IMDS → extract temporary credentials (AccessKeyId + SecretAccessKey + SessionToken)
        ↓
Configure stolen credentials in AWS CLI
        ↓
Enumerate permissions → identify accessible resources
        ↓
Access target resource → flag captured
```

---

### Key Concepts

- SSRF allows an attacker to make the server issue HTTP requests to arbitrary destinations, including internal metadata endpoints unreachable from the internet
- IMDSv1 requires no authentication — directly exploitable via SSRF; IMDSv2 requires a PUT-based session token that most SSRF contexts cannot forge
- Temporary credentials stolen from IMDS are fully functional until expiry, granting all permissions of the attached IAM role

---

### Tools Used

| Tool | Purpose |
|---|---|
| Burp Suite | SSRF vulnerability identification and request manipulation |
| `curl` | Direct IMDS endpoint interaction |
| AWS CLI | Authenticating with stolen credentials and accessing resources |

---

### Key Takeaways

> **1. IMDSv2 prevents this attack entirely.**
> Enforcing IMDSv2 on all EC2 instances (`HttpTokens: required`) is the single
> most effective mitigation. The PUT token requirement breaks SSRF-based IMDS access.

> **2. Apply least privilege to EC2 IAM roles.**
> The stolen role's permissions determine the blast radius.
> An over-permissioned role turns a medium SSRF into a critical breach.

> **3. Validate and allowlist server-side URL parameters.**
> Never allow user-controlled values to drive server-side HTTP requests
> without strict destination allowlisting.

---

### Defensive Recommendations

| Finding | Fix |
|---|---|
| IMDSv1 accessible | Enforce IMDSv2 — set `HttpTokens: required` on all EC2 instances |
| Over-permissioned instance role | Apply least privilege — minimum required actions and resources only |
| SSRF in application | Implement server-side URL allowlisting |
| No network-level block | Block egress to `169.254.169.254` for workloads that don't need IMDS |

---

### MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Exploit Public-Facing Application | T1190 | SSRF vulnerability exploitation |
| Unsecured Credentials in Metadata | T1552.007 | IMDS credential theft via SSRF |
| Valid Accounts — Cloud Accounts | T1078.004 | Using stolen IAM role credentials |
| Data from Cloud Storage | T1530 | Accessing protected resources with stolen credentials |

---

## Lab 02 — AWS IAM Privilege Escalation

**Cloud:** AWS
**Category:** IAM · Privilege Escalation · Serverless Abuse
**Difficulty:** Hard
**Result:** ✅ Completed

---

### Scenario

Starting with a low-privilege IAM user, enumerate the available permissions, identify a privilege escalation path via dangerous permission combinations, and escalate to administrator access to retrieve the flag from Secrets Manager.

---

### Attack Overview

The attack begins with systematic IAM permission enumeration to map what the starting identity is allowed to do. A dangerous combination is identified — the ability to create serverless functions and pass existing IAM roles to them. A function payload is crafted that, when executed with the higher-privileged role, performs an IAM action that elevates the attacker's own permissions. After invoking the function, administrator access is confirmed and the target secret is retrieved.

**High-level flow:**
```
Enumerate IAM permissions → identify dangerous combination
        ↓
Locate an existing high-privilege role that can be passed
        ↓
Create Lambda function with admin role attached (iam:PassRole)
        ↓
Function payload performs IAM escalation action
        ↓
Invoke function → attacker user elevated to admin
        ↓
Access Secrets Manager → flag captured
```

---

### Key Concepts

- Certain IAM permission combinations enable privilege escalation even when no single permission looks dangerous in isolation
- The ability to create a Lambda function and pass an existing admin role to it effectively grants the admin role's permissions to any code the attacker controls
- Over 40 documented AWS IAM privilege escalation paths exist — covering Lambda, EC2, ECS, Glue, CloudFormation, and more

---

### Tools Used

| Tool | Purpose |
|---|---|
| AWS CLI | Permission enumeration and resource interaction |
| Python + boto3 | Lambda function payload |
| `enumerate-iam` | Automated IAM permission brute-force (optional) |

---

### Key Takeaways

> **1. `iam:PassRole` + service creation = privilege escalation.**
> Any permission to create a compute resource combined with `iam:PassRole`
> can enable escalation to the passed role's permissions.

> **2. Audit privilege escalation paths proactively.**
> Tools like pMapper model IAM permissions as a graph and automatically
> identify escalation paths across all AWS accounts.

> **3. Monitor for escalation sequences in CloudTrail.**
> `CreateFunction` + `PassRole` + `InvokeFunction` in short succession
> from the same identity is a high-confidence escalation signal.

---

### Defensive Recommendations

| Finding | Fix |
|---|---|
| Unrestricted `iam:PassRole` | Add conditions — restrict to specific role ARNs and target services |
| Lambda creation granted broadly | Restrict `lambda:CreateFunction` to deployment roles only |
| No CloudTrail alerting | Alert on `PassRole` + `CreateFunction` in sequence from same identity |
| No escalation path audit | Run pMapper or Cloudsplaining regularly across all accounts |

---

### MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Valid Accounts — Cloud Accounts | T1078.004 | Starting with low-privilege IAM user |
| Abuse Elevation Control Mechanism | T1548 | IAM PassRole privilege escalation |
| Deploy Container / Serverless | T1610 | Lambda function creation and invocation |
| Credentials in Cloud Service | T1552 | Secrets Manager flag retrieval |

---

## Lab 03 — Azure IMDS Managed Identity Token Theft

**Cloud:** Azure
**Category:** Managed Identity · IMDS · Token Abuse · Key Vault
**Difficulty:** Medium
**Result:** ✅ Completed

---

### Scenario

From within an Azure VM, query the Azure Instance Metadata Service to extract a managed identity OAuth2 JWT access token, then use it to enumerate and access Azure Key Vault secrets.

---

### Attack Overview

Once inside the VM, the Azure IMDS endpoint is queried with the appropriate header to request an OAuth2 access token scoped to Azure Key Vault. The returned JWT is decoded to confirm the identity and role assignments. The token is then used as a Bearer credential against the Azure Key Vault REST API — first to enumerate available secrets, then to read the target value.

**High-level flow:**
```
Access Azure VM
        ↓
Query Azure IMDS → request OAuth2 token scoped to Key Vault
        ↓
Decode JWT → confirm managed identity roles and permissions
        ↓
Query Key Vault REST API with Bearer token → enumerate secrets
        ↓
Read target secret → flag captured
```

---

### Key Concepts

- Azure managed identities allow VMs and services to authenticate to Azure APIs without stored credentials — but any code running on the VM can request these tokens
- The IMDS token endpoint is accessible from within the VM at `169.254.169.254` with a simple HTTP request requiring only the `Metadata: true` header
- The scope of damage is determined entirely by the Azure RBAC roles assigned to the managed identity

---

### Tools Used

| Tool | Purpose |
|---|---|
| `curl` | IMDS endpoint queries and REST API calls |
| `base64` + `python3` | JWT token decoding and claims inspection |
| Azure CLI | Resource enumeration alternative |

---

### Key Takeaways

> **1. VM compromise = managed identity compromise.**
> Any code on the VM can obtain the managed identity token.
> Scope permissions to minimum required resources — never subscription-wide.

> **2. SSRF on Azure VMs leads directly to token theft.**
> If an application on the VM is SSRF-vulnerable, the managed identity token
> can be extracted remotely without needing a shell on the VM.

> **3. Audit managed identity role assignments regularly.**
> Subscription-wide `Contributor` or `Owner` on a managed identity turns
> any VM compromise into a full subscription takeover.

---

### Defensive Recommendations

| Finding | Fix |
|---|---|
| Over-permissioned managed identity | Scope to specific resource groups and minimum RBAC roles |
| Key Vault accessible broadly | Use Key Vault RBAC — assign only to identities that need specific secrets |
| No anomaly detection | Enable Microsoft Defender for Key Vault — alerts on unusual access |
| SSRF risk | Block egress to `169.254.169.254` from application containers via NSG |

---

### MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Unsecured Credentials in Metadata | T1552.007 | Azure IMDS JWT token extraction |
| Use Alternate Authentication Material | T1550.001 | Bearer token used for Key Vault API |
| Cloud Service Discovery | T1526 | Key Vault secret enumeration |
| Data from Cloud Storage | T1530 | Reading flag from Key Vault secret |

---

## Lab 04 — Azure Entra ID OAuth Exploitation

**Cloud:** Azure
**Category:** OAuth 2.0 · Entra ID · Token Abuse
**Difficulty:** Hard
**Result:** ✅ Completed

---

### Scenario

An Azure application registration has a misconfigured OAuth flow enabled. Exploit the misconfiguration to capture an access token and use it to access protected Azure resources.

---

### Attack Overview

Reconnaissance of the target application reveals Azure app registration details embedded in client-side code. The app registration is found to have the OAuth implicit grant flow enabled — a deprecated flow that returns access tokens directly in the URL fragment. A crafted authorization URL triggers token issuance. The returned JWT is decoded to confirm granted permissions and identify accessible resources. The token is used directly against Azure REST APIs to access the target.

**High-level flow:**
```
Discover app registration details in page source (client_id, tenant_id)
        ↓
Identify implicit grant flow enabled on the app registration
        ↓
Craft authorization URL → token returned in URL fragment
        ↓
Decode JWT → confirm roles and accessible resources
        ↓
Use Bearer token against Azure REST API → access target
        ↓
Flag captured
```

---

### Key Concepts

- OAuth implicit flow returns tokens in the URL `#fragment` — visible in browser history, server logs, and JavaScript, making them trivially stealable
- App registration client IDs are frequently exposed in web source code — the implicit flow misconfiguration is what makes this dangerous
- JWT access tokens are self-contained — no server round-trip needed, valid until expiry

---

### Tools Used

| Tool | Purpose |
|---|---|
| Browser DevTools | Locating app registration details in page source |
| Burp Suite | HTTP request interception and manipulation |
| `curl` | REST API calls with captured token |
| `base64` + `python3` | JWT decoding and claims analysis |

---

### Key Takeaways

> **1. Disable OAuth implicit grant flow for all app registrations.**
> It is deprecated for good reason — tokens in URLs are inherently insecure.
> Use Authorization Code flow with PKCE for all clients, including SPAs.

> **2. Treat the client_id as public — the flow is the control.**
> Exposing a client_id is not dangerous in itself. The implicit flow
> misconfiguration is what enables token theft without valid credentials.

> **3. Audit app registrations for implicit flow at scale.**
> Use Azure CLI or Microsoft Graph to enumerate all app registrations
> and flag any with implicit flow enabled.

---

### Defensive Recommendations

| Finding | Fix |
|---|---|
| Implicit grant flow enabled | Disable in App Registration → Authentication → uncheck token types |
| Wildcard redirect URIs | Use exact, specific redirect URIs only |
| No Conditional Access | Enforce MFA + managed device requirements via Conditional Access |
| Long token lifetime | Create token lifetime policies to shorten access token TTL |

---

### MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Steal Application Access Token | T1528 | OAuth implicit flow token capture |
| Use Alternate Authentication Material | T1550.001 | Using stolen Bearer token for API access |
| Cloud Service Discovery | T1526 | Enumerating accessible Azure resources |
| Data from Cloud Storage | T1530 | Accessing protected resource with token |

---

## Labs Summary

| Lab | Cloud | Category | Key Technique |
|---|---|---|---|
| 01 | AWS | SSRF · IMDS | EC2 metadata credential theft via SSRF |
| 02 | AWS | IAM · Privesc | PassRole + Lambda privilege escalation |
| 03 | Azure | Managed Identity | IMDS JWT token theft from VM |
| 04 | Azure | OAuth · Entra ID | Implicit flow access token capture |

---

## Recommended Resources

- [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/)
- [AWS IAM Privilege Escalation Methods — Rhino Security Labs](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)
- [CloudGoat-OCI](https://github.com/CyberAI-Agency/CloudGoat-OCI) — Practice OCI attack scenarios
- [Awesome Cloud Security](https://github.com/CyberAI-Agency/awesome-cloud-sec)
- [Cyberwarfare Labs](https://cyberwarfare.live) — MCRTA certification

---

*[← Back to CTF Notes Index](../README.md)*

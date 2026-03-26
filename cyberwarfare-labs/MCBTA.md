# MCBTA — Multi-Cloud Blue Team Analyst

**Certification:** Multi-Cloud Blue Team Analyst (MCBTA)
**Provider:** Cyberwarfare Labs
**Platform:** ELK Stack (Elasticsearch + Kibana)
**Result:** ✅ 30/30 Challenges Completed

> ⚠️ **Provider Notice:** Per Cyberwarfare Labs' terms of service, detailed
> challenge solutions and specific log queries are not shared publicly.
> Detection approaches below are described at a conceptual level for
> educational reference only.
>
> To attempt these labs yourself, visit: [cyberwarfare.live](https://cyberwarfare.live)

---

## Challenge 01 — Detecting IAM Enumeration (AWS)

**Cloud:** AWS
**Log Source:** AWS CloudTrail
**Category:** Discovery · IAM Analysis
**Difficulty:** Easy
**Result:** ✅ Completed

---

### Scenario

Identify which identity performed systematic IAM enumeration in an AWS account by analysing CloudTrail logs in Kibana.

---

### Detection Overview

IAM enumeration leaves a distinctive pattern in CloudTrail — a burst of `List*` and `Describe*` API calls against IAM services from the same identity within a short time window. The goal is to identify the source identity, the time window, and the scope of what was enumerated.

**Detection approach:**
```
Filter CloudTrail logs for IAM-related API calls (ListUsers, ListRoles, ListPolicies etc.)
        ↓
Aggregate by identity and time window
        ↓
Identify anomalous burst — significantly more calls than baseline
        ↓
Confirm source identity and enumerate what was accessed
```

---

### Key Concepts

- Legitimate admin activity involves occasional IAM calls; automated enumeration produces dozens of calls per minute
- `GetAccountAuthorizationDetails` is a particularly high-signal call — it returns the entire IAM configuration in one request and is rarely called outside of security tooling
- Correlating enumeration with subsequent suspicious activity (CreateFunction, AssumeRole) reveals the full attack chain

---

### Tools Used

| Tool | Purpose |
|---|---|
| Kibana Discover | Log filtering and investigation |
| KQL | CloudTrail event filtering and aggregation |
| Kibana Lens | Time-series visualisation of API call frequency |

---

### Key Takeaways

> **1. Baseline API call frequency per identity.**
> Enumeration stands out only when you know what normal looks like.
> Establish per-role and per-user call baselines for IAM services.

> **2. `GetAccountAuthorizationDetails` is a red flag.**
> This single API call returns all IAM users, groups, roles, and policies.
> It should almost never appear in production CloudTrail logs from human users.

> **3. Volume alone is not enough — look for breadth.**
> An attacker enumerates many different resource types quickly.
> Legitimate admins tend to work within a narrow set of services.

---

### Defensive Recommendations

| Finding | Fix |
|---|---|
| No IAM enumeration alert | Create CloudTrail alert: >15 IAM list calls from same identity in 5 min |
| Broad IAM read permissions | Restrict `iam:List*` and `iam:Get*` to roles that genuinely need it |
| No SIEM baseline | Establish call frequency baselines using 30-day rolling averages |

---

### MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Cloud Infrastructure Discovery | T1580 | Enumerating IAM resources |
| Permission Groups Discovery | T1069.003 | Listing IAM groups and roles |
| Account Discovery — Cloud Account | T1087.004 | Listing IAM users |

---

## Challenge 02 — Detecting IMDS Credential Theft (AWS)

**Cloud:** AWS
**Log Source:** AWS CloudTrail
**Category:** Credential Access · Lateral Movement
**Difficulty:** Medium
**Result:** ✅ Completed

---

### Scenario

Identify evidence of EC2 IMDS credential theft by analysing the usage patterns of a specific IAM role in CloudTrail — specifically, usage originating from an unexpected source.

---

### Detection Overview

When EC2 IMDS credentials are stolen and used externally, they produce a distinctive anomaly in CloudTrail: an IAM role that is normally used from within the AWS IP space is suddenly used from a public IP address outside AWS. The detection pivots on identifying this geographic and source IP anomaly.

**Detection approach:**
```
Filter CloudTrail for AssumedRole events from the target role
        ↓
Extract source IP addresses for each usage event
        ↓
Identify calls originating from non-AWS IP ranges
        ↓
Confirm the external IP is not a known corporate egress IP
        ↓
Corroborate with timeline of SSRF or unusual web requests on the EC2
```

---

### Key Concepts

- EC2 instance role credentials should only ever be used from within AWS IP ranges (except for very specific VPN/Direct Connect scenarios)
- AWS publishes its IP ranges in a JSON file — any role usage from IPs outside this list is immediately suspicious
- Temporary credentials from IMDS include a session token; CloudTrail records show the `sessionIssuer` as the EC2 instance role

---

### Tools Used

| Tool | Purpose |
|---|---|
| Kibana Discover | CloudTrail log filtering |
| KQL | AssumedRole event filtering with IP analysis |
| AWS IP Range lookup | Confirming whether source IP belongs to AWS |

---

### Key Takeaways

> **1. EC2 role usage from non-AWS IPs is always suspicious.**
> Build a detection rule specifically for this pattern — it has very few
> legitimate explanations and high attack signal.

> **2. Correlate with web application logs.**
> The SSRF exploitation that enabled the theft will appear in the application
> or load balancer access logs shortly before the credential usage anomaly.

> **3. Short-lived credentials don't mean low risk.**
> IMDS credentials typically have a 1-6 hour TTL — enough time to cause
> significant damage if the attached role has broad permissions.

---

### Defensive Recommendations

| Finding | Fix |
|---|---|
| No external role usage alert | Alert on: EC2 role used from non-AWS source IP |
| IMDSv1 enabled | Enforce IMDSv2 on all EC2 instances |
| SSRF not detected | Implement WAF rules detecting requests to internal IP ranges |

---

### MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Unsecured Credentials in Metadata | T1552.007 | IMDS credential theft indicator |
| Valid Accounts — Cloud Accounts | T1078.004 | Stolen role used from external IP |
| Lateral Movement via Cloud Services | T1550 | Pivoting with stolen credentials |

---

## Challenge 03 — Detecting Lambda Privilege Escalation (AWS)

**Cloud:** AWS
**Log Source:** AWS CloudTrail
**Category:** Privilege Escalation · Serverless
**Difficulty:** Hard
**Result:** ✅ Completed

---

### Scenario

Identify a Lambda-based IAM privilege escalation attack by correlating a sequence of CloudTrail events that individually look innocuous but together form a clear attack chain.

---

### Detection Overview

The attack leaves a specific sequence of CloudTrail events across a short time window. Detecting it requires correlating events by the same identity rather than treating each API call in isolation.

**Detection approach:**
```
Filter for Lambda creation events (CreateFunction)
        ↓
Check if the creating identity also called PassRole around the same time
        ↓
Identify the role passed — is it significantly more privileged than the caller?
        ↓
Check for InvokeFunction shortly after CreateFunction
        ↓
Check for IAM modification events (AttachUserPolicy, CreateAccessKey) by the Lambda execution role
        ↓
Confirm the escalation: creator's permissions before vs. after
```

---

### Key Concepts

- Each step of the attack looks legitimate in isolation — creating functions and invoking them is normal developer activity
- The escalation signal is the combination: `CreateFunction` + `PassRole` to a higher-privilege role + `InvokeFunction` + subsequent IAM change
- Time correlation is critical — these events occur within minutes of each other during an attack

---

### Tools Used

| Tool | Purpose |
|---|---|
| Kibana Discover | Multi-event correlation |
| KQL | Sequence detection across CloudTrail event types |
| Kibana Lens | Timeline visualisation of event sequence |

---

### Key Takeaways

> **1. Attack chains are invisible without event correlation.**
> Each event in this chain passes individual scrutiny.
> Detection requires sequencing events by identity and time.

> **2. `PassRole` to a more privileged role is always worth investigating.**
> Build a detection that alerts when a user passes a role that has
> significantly more permissions than the user themselves.

> **3. Monitor for IAM changes by Lambda execution roles.**
> A Lambda function calling `AttachUserPolicy` or `CreateAccessKey` is
> highly anomalous and should trigger an immediate alert.

---

### Defensive Recommendations

| Finding | Fix |
|---|---|
| No escalation chain detection | Build multi-event correlation rule for the full sequence |
| Unrestricted PassRole | Constrain with IAM conditions on role ARN and service |
| Lambda can modify IAM | Apply permission boundary to Lambda execution roles |

---

### MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Abuse Elevation Control Mechanism | T1548 | PassRole + Lambda privilege escalation |
| Create or Modify Cloud Compute | T1578 | Lambda function creation |
| Account Manipulation | T1098 | IAM policy attachment via Lambda |

---

## Challenge 04 — Detecting Impossible Travel (Azure)

**Cloud:** Azure
**Log Source:** Azure AD Sign-in Logs
**Category:** Identity · Credential Compromise
**Difficulty:** Easy
**Result:** ✅ Completed

---

### Scenario

Identify a compromised account by detecting geographically impossible sign-in activity in Azure AD logs.

---

### Detection Overview

Impossible travel occurs when the same identity authenticates from two geographic locations within a time window that makes physical travel between them impossible. The detection requires calculating the time delta between consecutive sign-in events for the same user and comparing it against realistic travel time.

**Detection approach:**
```
Filter sign-in logs for successful authentications
        ↓
Group events by user identity
        ↓
For each user, sort events chronologically
        ↓
Calculate time between consecutive sign-ins from different locations
        ↓
Flag cases where geographic distance > (time delta × max travel speed)
        ↓
Exclude known VPN egress IPs and corporate proxy addresses
```

---

### Key Concepts

- Impossible travel is a high-confidence signal when false positives from VPNs and proxies are accounted for
- The sign-in logs include IP address, city, country, and a Microsoft-calculated risk score — but the detection logic should not rely solely on Microsoft's built-in risk scoring
- A 15-minute gap between sign-ins from different continents is impossible without compromised credentials or token theft

---

### Tools Used

| Tool | Purpose |
|---|---|
| Kibana Discover | Azure AD sign-in log filtering |
| KQL | Time delta calculation and geo correlation |
| IP geolocation lookup | Confirming location of source IPs |

---

### Key Takeaways

> **1. Impossible travel is a near-certain credential compromise indicator.**
> When confirmed (VPN/proxy excluded), treat it as a confirmed breach —
> not just a suspicious event requiring further investigation.

> **2. Build an allowlist of known corporate IP ranges.**
> VPN and proxy traffic creates false positives. Maintaining an IP allowlist
> dramatically improves the signal-to-noise ratio of travel-based detections.

> **3. Correlate with resource access after the anomalous sign-in.**
> Knowing the attacker accessed the account is less valuable than knowing
> what they accessed. Follow the timeline of events after the flagged sign-in.

---

### Defensive Recommendations

| Finding | Fix |
|---|---|
| No impossible travel detection | Enable Entra ID Identity Protection risk policy for impossible travel |
| No MFA on account | Enforce MFA via Conditional Access for all users |
| No session anomaly detection | Enable Microsoft Defender for Identity |

---

### MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Valid Accounts — Cloud Accounts | T1078.004 | Compromised identity used from external location |
| Use Alternate Authentication Material | T1550 | Session or token used from unexpected location |

---

## Challenge 05 — Detecting DNS Tunneling (Network)

**Cloud:** Multi-cloud
**Log Source:** DNS Query Logs · VPC Flow Logs
**Category:** Command and Control · Exfiltration
**Difficulty:** Hard
**Result:** ✅ Completed

---

### Scenario

Identify data exfiltration or C2 communication occurring via DNS tunneling by analysing DNS query logs for anomalous patterns.

---

### Detection Overview

DNS tunneling encodes data within DNS query names, producing queries that are longer, more random-looking, and more frequent than legitimate DNS traffic. The detection focuses on identifying these statistical anomalies rather than matching specific domains.

**Detection approach:**
```
Aggregate DNS query volume per source IP and destination domain
        ↓
Flag domains with abnormally high query frequency from a single source
        ↓
Analyse query name length distribution — tunneling produces longer names
        ↓
Check for high proportion of TXT record queries (common in tunneling tools)
        ↓
Calculate query name entropy — encoded data has higher entropy than normal hostnames
        ↓
Corroborate with network flow data showing unusual traffic to the same destination
```

---

### Key Concepts

- DNS is allowed through almost every firewall — it is one of the most reliable exfiltration channels available to attackers
- Tunneling tools like `dnscat2` and `iodine` encode data in query names, producing subdomains like `aGVsbG8gd29ybGQ.attacker.com`
- Statistical detection (query frequency, name length, entropy) is more robust than blocklist-based detection for unknown tunneling domains

---

### Tools Used

| Tool | Purpose |
|---|---|
| Kibana Discover | DNS log filtering and aggregation |
| KQL | Query frequency and length analysis |
| Kibana Lens | Domain query frequency visualisation |

---

### Key Takeaways

> **1. High-frequency queries to a single domain from one host are suspicious.**
> Legitimate DNS resolvers cache responses — repeated queries for the same
> base domain subdomains indicate active data encoding.

> **2. Entropy analysis is powerful for encoded content detection.**
> Normal hostnames have low entropy (dictionary words, short labels).
> Base64 or hex-encoded data has significantly higher entropy.

> **3. DNS logging is often incomplete or absent.**
> Many organisations log only firewall events and miss DNS-level visibility.
> Implement DNS query logging as a baseline security control.

---

### Defensive Recommendations

| Finding | Fix |
|---|---|
| No DNS query logging | Enable DNS query logging at resolver level — send to SIEM |
| No tunneling detection | Implement frequency + entropy-based detection rules |
| Unrestricted DNS egress | Route all DNS through monitored internal resolvers; block direct port 53 |

---

### MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Application Layer Protocol — DNS | T1071.004 | DNS tunneling for C2 or exfiltration |
| Exfiltration Over Alternative Protocol | T1048 | Data exfiltration encoded in DNS queries |
| Non-Standard Port | T1571 | DNS over non-standard resolver |

---

## Challenges Summary

| # | Cloud | Category | Key Detection Technique |
|---|---|---|---|
| 01 | AWS | IAM Enumeration | API call burst detection in CloudTrail |
| 02 | AWS | IMDS Credential Theft | EC2 role used from non-AWS source IP |
| 03 | AWS | Lambda Privesc | Multi-event chain correlation |
| 04 | Azure | Impossible Travel | Geographic sign-in time delta analysis |
| 05 | Multi | DNS Tunneling | Query frequency + entropy analysis |
| 06–30 | AWS · Azure · GCP | Various | CloudTrail · Azure Monitor · GCP Audit · Flow Logs |

> Additional challenges covered: GCS exfiltration detection, Azure Key Vault anomalies,
> GCP IAM policy changes, lateral movement in VPC flow logs, C2 beacon pattern detection,
> and more — all following the same detection-first, evidence-driven approach above.

---

## Recommended Resources

- [Elastic SIEM Detection Rules](https://github.com/elastic/detection-rules) — Production-ready ELK detection rules
- [Sigma Rules](https://github.com/SigmaHQ/sigma) — Generic detection rule format, convertible to KQL
- [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/)
- [AWS CloudTrail Event Reference](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html)
- [ThreatHunterAI](https://github.com/CyberAI-Agency/ThreatHunterAI) — AI-driven SIEM threat hunting agent
- [Cyberwarfare Labs](https://cyberwarfare.live) — MCBTA certification

---

*[← Back to CTF Notes Index](../README.md)*

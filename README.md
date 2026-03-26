# CTF Notes — Cloud Security Write-ups 🏴‍☠️

> Detailed write-ups from real cloud security CTF competitions and certification labs.
> Attack paths, tools used, key takeaways, and MITRE ATT&CK mappings.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![Wiz CTF](https://img.shields.io/badge/Wiz_CTF-5_Wins-FF6600?style=flat-square)](https://www.wiz.io/lp/wiz-ctf)
[![MCRTA](https://img.shields.io/badge/MCRTA-Certified-4D148C?style=flat-square)](https://cyberwarfare.live)
[![MCBTA](https://img.shields.io/badge/MCBTA-30%2F30-00C875?style=flat-square)](https://cyberwarfare.live)

By [@nvsaigeetham](https://github.com/nvsaigeetham) · [CyberAI Agency](https://github.com/CyberAI-Agency)

---

## 📁 Repo Structure

```
ctf-notes/
├── README.md                          ← You are here (index)
│
├── wiz-ctf/
│   ├── 01-needle-in-a-haystack.md    ← Web/OSINT · Client-side auth bypass
│   ├── 02-game-of-pods.md            ← Kubernetes RBAC · CVE-2024-3177
│   ├── 03-contain-me-if-you-can.md   ← Container escape via PostgreSQL
│   ├── 04-breaking-the-barriers.md   ← Azure OAuth · Entra ID exploitation
│   └── 05-malware-busters.md         ← Golang malware RE · Dual-layer decryption
│
├── mcrta-labs/
│   ├── 01-aws-ssrf-imds.md           ← AWS SSRF → EC2 IMDS credential theft
│   ├── 02-aws-iam-privesc.md         ← AWS IAM privilege escalation
│   └── 03-azure-imds-jwt.md          ← Azure IMDS JWT token extraction
│
└── mcbta-labs/
    └── 01-siem-challenges.md          ← ELK/Kibana · 30/30 challenges
```

---

## 🏆 Wiz CTF Challenges

| # | Challenge | Category | Difficulty | Key Technique |
|---|---|---|---|---|
| 01 | [Needle in a Haystack](./wiz-ctf/01-needle-in-a-haystack.md) | Web / OSINT | Medium | Client-side auth bypass |
| 02 | [Game of Pods](./wiz-ctf/02-game-of-pods.md) | Kubernetes | Hard | RBAC abuse · CVE-2024-3177 |
| 03 | [Contain Me If You Can](./wiz-ctf/03-contain-me-if-you-can.md) | Container | Hard | PostgreSQL COPY FROM PROGRAM |
| 04 | [Breaking The Barriers](./wiz-ctf/04-breaking-the-barriers.md) | Azure | Hard | OAuth implicit flow · Entra ID |
| 05 | [Malware Busters](./wiz-ctf/05-malware-busters.md) | Reverse Engineering | Hard | Golang RE · XOR + AES decryption |

---

## ☁️ MCRTA Labs — Multi-Cloud Red Team

| # | Lab | Cloud | Key Technique |
|---|---|---|---|
| 01 | [AWS SSRF → IMDS Credential Theft](./mcrta-labs/01-aws-ssrf-imds.md) | AWS | SSRF · EC2 metadata service |
| 02 | [AWS IAM Privilege Escalation](./mcrta-labs/02-aws-iam-privesc.md) | AWS | PassRole · Lambda abuse |
| 03 | [Azure IMDS JWT Extraction](./mcrta-labs/03-azure-imds-jwt.md) | Azure | Managed identity token theft |

---

## 🔵 MCBTA Labs — Multi-Cloud Blue Team

| # | Lab | Challenges | Result |
|---|---|---|---|
| 01 | [ELK/Kibana SIEM Challenges](./mcbta-labs/01-siem-challenges.md) | 30 challenges across AWS · Azure · GCP | 30/30 ✅ |

---

## 🗺️ MITRE ATT&CK Coverage

| Technique | ID | Covered In |
|---|---|---|
| Gather Victim Host Information | T1592 | Needle in a Haystack |
| Exploit Public-Facing Application | T1190 | Needle in a Haystack |
| Deploy Container | T1610 | Game of Pods |
| Escape to Host | T1611 | Game of Pods · Contain Me |
| Container API Credential Access | T1552.007 | Game of Pods · Contain Me |
| Command and Scripting Interpreter | T1059 | Contain Me If You Can |
| Application Access Token Abuse | T1550.001 | Breaking The Barriers |
| Steal Application Access Token | T1528 | Breaking The Barriers |
| Obfuscated Files / Information | T1027 | Malware Busters |
| Server-Side Request Forgery | T1190 | AWS SSRF Lab |
| Unsecured Credentials in Metadata | T1552.007 | AWS SSRF · Azure IMDS |
| Valid Accounts — Cloud Accounts | T1078.004 | AWS IAM Privesc |

---

## 🛠️ Tools Used Across Challenges

```
Reconnaissance   → subfinder · amass · GitHub OSINT
Web Analysis     → Burp Suite · curl · Browser DevTools
Cloud            → AWS CLI · Azure CLI · kubectl · psql
Reverse Eng.     → Ghidra · strings · file · ltrace · strace
Scripting        → Python · pycryptodome · base64
SIEM             → ELK Stack · Kibana · KQL
```

---

## 📚 Related Resources

- [CloudGoat-OCI](https://github.com/CyberAI-Agency/CloudGoat-OCI) — Practice OCI attack scenarios (built by us)
- [Awesome Cloud Security](https://github.com/CyberAI-Agency/awesome-cloud-sec) — Curated security tools list
- [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/)
- [Wiz CTF](https://www.wiz.io/lp/wiz-ctf) — Cloud security CTF platform

---

## 🤝 Contributing

Have cloud security CTF write-ups to share? PRs are welcome!

- Add your write-up in the appropriate folder
- Follow the existing template structure (scenario → attack path → tools → takeaways → MITRE)
- Redact any sensitive or identifying information before submitting
- See [CONTRIBUTING.md](CONTRIBUTING.md) for full guidelines

---

## License

MIT License · © 2026 [@nvsaigeetham](https://github.com/nvsaigeetham)

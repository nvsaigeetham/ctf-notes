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
├── README.md                              ← You are here
│
├── wiz-ctf/                               ← Full detailed write-ups
│   ├── 01-needle-in-a-haystack.md
│   ├── 02-game-of-pods.md
│   ├── 03-contain-me-if-you-can.md
│   ├── 04-breaking-the-barriers.md
│   └── 05-malware-busters.md
│
└── cyberwarfare-labs/                     ← High-level overviews only
    ├── MCBTA.md
    └── MCRTA.md
```

> ⚠️ **Note on Cyberwarfare Labs content:** Per provider guidelines, detailed
> step-by-step solutions for MCRTA and MCBTA certification lab challenges are
> not shared publicly. Only high-level attack/defense category overviews are provided.

---

## 🏆 Wiz CTF — Full Write-ups

| # | Challenge | Category | Difficulty | Key Technique |
|---|---|---|---|---|
| 01 | [Needle in a Haystack](./wiz-ctf/01-needle-in-a-haystack.md) | Web / OSINT | Medium | Client-side auth bypass |
| 02 | [Game of Pods](./wiz-ctf/02-game-of-pods.md) | Kubernetes | Hard | RBAC abuse · CVE-2024-3177 |
| 03 | [Contain Me If You Can](./wiz-ctf/03-contain-me-if-you-can.md) | Container Escape | Hard | PostgreSQL COPY FROM PROGRAM |
| 04 | [Breaking The Barriers](./wiz-ctf/04-breaking-the-barriers.md) | Azure / OAuth | Hard | Implicit flow token theft · Entra ID |
| 05 | [Malware Busters](./wiz-ctf/05-malware-busters.md) | Reverse Engineering | Hard | Golang RE · XOR + AES-256-CBC |

---

## 🎓 Cyberwarfare Labs — Certification Overviews

| Certification | File | Clouds | Focus |
|---|---|---|---|
| MCRTA — Multi-Cloud Red Team Analyst | [MCRTA.md](./cyberwarfare-labs/MCRTA.md) | AWS · Azure | Offensive — SSRF, IAM privesc, OAuth abuse |
| MCBTA — Multi-Cloud Blue Team Analyst | [MCBTA.md](./cyberwarfare-labs/MCBTA.md) | AWS · Azure · GCP | Defensive — ELK/Kibana SIEM, 30/30 challenges |

---

## 🗺️ MITRE ATT&CK Coverage

| Technique | ID | Source |
|---|---|---|
| Search Open Websites/Domains | T1593 | Needle in a Haystack |
| Gather Victim Host Information | T1592 | Needle in a Haystack |
| Exploit Public-Facing Application | T1190 | Needle in a Haystack |
| Credentials in Files | T1552.001 | Needle in a Haystack |
| Deploy Container | T1610 | Game of Pods |
| Escape to Host | T1611 | Game of Pods · Contain Me |
| Container API Credential Access | T1552.007 | Game of Pods · Contain Me |
| Command and Scripting Interpreter | T1059 | Contain Me If You Can |
| Data from Local System | T1005 | Contain Me If You Can |
| Steal Application Access Token | T1528 | Breaking The Barriers |
| Use Alternate Authentication Material | T1550.001 | Breaking The Barriers |
| Cloud Service Discovery | T1526 | Breaking The Barriers |
| Data from Cloud Storage | T1530 | Breaking The Barriers |
| Obfuscated Files or Information | T1027 | Malware Busters |
| Software Packing | T1027.002 | Malware Busters |

---

## 🛠️ Tools Referenced

```
Reconnaissance   → subfinder · amass · GitHub OSINT
Web Testing      → Burp Suite · curl · Browser DevTools
Cloud            → AWS CLI · Azure CLI · kubectl
Database         → psql (PostgreSQL client)
Reverse Eng.     → Ghidra · strings · file · go tool objdump
Scripting        → Python 3 · pycryptodome
SIEM             → ELK Stack · Kibana · KQL
```

---

## 📚 Related Resources

- [CloudGoat-OCI](https://github.com/CyberAI-Agency/CloudGoat-OCI) — Practice OCI attack scenarios
- [Awesome Cloud Security](https://github.com/CyberAI-Agency/awesome-cloud-sec) — Curated security tools list
- [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/)
- [Wiz CTF Platform](https://www.wiz.io/lp/wiz-ctf)
- [Cyberwarfare Labs](https://cyberwarfare.live) — MCRTA / MCBTA certifications

---

## 🤝 Contributing

Have public CTF write-ups to share? PRs welcome!

- Only write-ups for **publicly available, free CTFs** are accepted
- Follow the existing template: scenario → steps → tools → takeaways → MITRE
- Do **not** share solutions for paid certification labs — respect provider terms
- See [CONTRIBUTING.md](CONTRIBUTING.md) for full guidelines

---

## License

MIT License · © 2026 [@nvsaigeetham](https://github.com/nvsaigeetham)

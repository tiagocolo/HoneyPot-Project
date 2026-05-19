# SSH Honeypot — SOC L1 Analysis with Microsoft Sentinel

This project documents a real attack captured on an intentionally exposed DigitalOcean droplet. The goal was to simulate a SOC L1 workflow end-to-end: receive an alert, investigate through the SIEM, and escalate with a complete evidence package.

---

## Environment

| | |
|---|---|
| **Honeypot host** | DigitalOcean Droplet — Ubuntu 24.04 |
| **SIEM** | Microsoft Sentinel |
| **Log forwarding** | Azure Monitor Agent → Syslog table |
| **Exposure** | SSH port 22, root login enabled, weak password |
| **Period** | May 12–13, 2026 |

---

## Repository Structure

```
ssh-honeypot-soc-analysis/
├── README.md
├── queries/
│   └── kql_queries.md
├── report/
│   └── incident_report.md
└── evidence/
    ├── 01_CPU_USAGE
    ├── 02_CRON
    ├── 03_SIGN_IN_ATTEMPTS
    ├── 04_SUCCESFUL_SIGN_IN
    └── 05_UFW_BLOCK
```

---

## What Happened

The droplet was exposed on May 12. Within hours, automated brute force bots started hitting port 22. By May 13, three of them had gotten in.

### Brute Force (May 12)

Many IPs ran credential stuffing attacks against the root account. The most aggressive one — `192.227.173.105` — made 1,400 attempts on its own.

**MITRE:** T1110.001 — Brute Force: Password Guessing

### Initial Access (May 13)

Three IPs successfully authenticated as root:

| Time | IP | Port |
|---|---|---|
| 1:08:31 PM | 92.118.39.236 | 15808 |
| 1:08:40 PM | 172.82.91.35 | 37224 |
| 1:39:59 PM | 45.156.87.69 | 47794 |

All three had previously appeared in the failed login logs, so these weren't separate actors — they were part of the same brute force campaign that eventually found the right password.

**MITRE:** T1078 — Valid Accounts

### Persistence (May 13)

After getting in, the attacker dropped a script at `/etc/cron.hourly/gcc.sh`. The filename is deliberate — `gcc` is the GNU C Compiler, a standard Linux binary, so it blends in. The script ran every hour as root via cron.

Sentinel showed this repeating every hour:
```
(root) CMD (/etc/cron.hourly/gcc.sh)
pam_unix(cron:session): session opened for user root(uid=0) by root(uid=0)
pam_unix(cron:session): session closed for user root
```

**MITRE:** T1053.003 — Cron / T1036 — Masquerading

### Impact (May 13)

CPU climbed to 65.1% and kept rising, There is probably a criptominer.

**MITRE:** T1496 — Resource Hijacking

### Defense Evasion (May 13)

UFW was modified to block inbound connections on port 22. 1,519 UFW BLOCK events appeared in Sentinel, all targeting the host. The attacker locked themselves in and locked everyone else out.

**MITRE:** T1562.004 — Disable or Modify System Firewall

---

## MITRE ATT&CK Summary

| Tactic | Technique | ID |
|---|---|---|
| Credential Access | Brute Force: Password Guessing | T1110.001 |
| Initial Access | Valid Accounts | T1078 |
| Execution | Scheduled Task/Job: Cron | T1053.003 |
| Persistence | Scheduled Task/Job: Cron | T1053.003 |
| Defense Evasion | Masquerading | T1036 |
| Defense Evasion | Disable or Modify System Firewall | T1562.004 |
| Impact | Resource Hijacking | T1496 |

---

## IOCs

**IPs that successfully authenticated:**
```
45.156.87.69
172.82.91.35
92.118.39.236
```

**Top brute force sources:**
```
192.227.173.105  — 1,400 attempts
167.99.148.102   — 787 attempts
192.109.200.78   — 685 attempts
45.156.87.253    — 685 attempts
159.223.115.49   — 381 attempts
```

**Malicious file:**
```
/etc/cron.hourly/gcc.sh
```

---

## Tools

| Tool | Use |
|---|---|
| Microsoft Sentinel | SIEM — alerting, KQL investigation, incident tracking |
| Azure Monitor Agent | Log forwarding from honeypot to Sentinel |
| KQL | Log querying and IOC correlation |
| DigitalOcean | Honeypot infrastructure |
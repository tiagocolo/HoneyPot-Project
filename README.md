# Honeypot SOC Analysis

A real attack captured on an intentionally exposed DigitalOcean droplet. This project follows a SOC L1 workflow end-to-end: receive an alert, investigate through Microsoft Sentinel, trace the full attack chain, and produce a professional incident report.

**Period:** May 12-13, 2026  
**Platform:** DigitalOcean Droplet — Ubuntu 24.04  
**SIEM:** Microsoft Sentinel (Azure Monitor Agent → Syslog)  
**Exposure:** SSH port 22, root login enabled, weak password

> Note: I did not configure auditd on this machine, so some logs are missing. The investigation was done with what was available.

---

## Attack Timeline

```
May 12                May 13
  |                      |
  | 12:00  ──  Brute force begins (1,400+ attempts)
  |                      |
  |                      | 13:08  ──  First successful root login
  |                      | 13:08  ──  Second successful root login
  |                      | 13:39  ──  Third successful root login
  |                      | 13:40  ──  Cron persistence installed (gcc.sh)
  |                      | 13:45  ──  CPU spikes to 65% (cryptominer)
  |                      | 14:00  ──  UFW blocks port 22 (attacker locks everyone out)
```

---

## What happened

### 1. Brute Force (T1110.001)

The droplet was exposed on May 12. Within hours, automated bots started hitting port 22. The most aggressive IP — `192.227.173.105` — made **1,400 attempts** on its own.

**Top sources:**
| IP | Attempts |
|----|----------|
| 192.227.173.105 | 1,400 |
| 167.99.148.102 | 787 |
| 192.109.200.78 | 685 |
| 45.156.87.253 | 685 |
| 159.223.115.49 | 381 |

### 2. Successful Access (T1078)

Three IPs successfully authenticated as root:

| Time | IP | Port |
|------|----|------|
| 13:08:31 | 92.118.39.236 | 15808 |
| 13:08:40 | 172.82.91.35 | 37224 |
| 13:39:59 | 45.156.87.69 | 47794 |

The third IP (`172.82.91.35`) had a clean reputation on AbuseIPDB and VirusTotal — but it was the same attacker from `92.118.39.236` switching IPs to masquerade as a legitimate user after stealing credentials.

### 3. Persistence via Cron (T1053.003)

The attacker dropped a script at `/etc/cron.hourly/gcc.sh`. The name is deliberate — `gcc` is the GNU C Compiler, a standard Linux binary. The attacker was trying to hide in plain sight.

### 4. Resource Hijacking (T1496)

CPU climbed to 65.1% and kept rising — consistent with a cryptominer.

### 5. Firewall Changes (T1562.004)

UFW was modified to block inbound connections on port 22. The attacker locked themselves in and locked everyone else out.

---

## Evidence

Screenshots from Microsoft Sentinel showing the investigation:

| Screenshot | Description |
|------------|-------------|
| [Sign-in attempts](./Evidence/SIGN_IN_ATTEMPS.webp) | Failed root login attempts in Sentinel |
| [Successful sign-ins](./Evidence/SUCCESFUL_SIGN_IN.webp) | Three successful root authentications |
| [CPU spike](./Evidence/CPU_USAGE.webp) | CPU usage climbing to 65% |
| [Cron persistence](./Evidence/CRON.webp) | gcc.sh script detected in cron |
| [UFW blocks](./Evidence/UFW_BLOCK.webp) | Firewall changes blocking port 22 |

### Threat Intelligence

VirusTotal and AbuseIPDB lookups for the attacker IPs:

**92.118.39.236** — Malicious  
[VirusTotal](./threat-intel/VirusTotal-ip-92.118.39.236.png) | [AbuseIPDB](./threat-intel/AbuseIPDB-ip-92.118.39.236.png)

**45.156.87.69** — Malicious  
[VirusTotal](./threat-intel/VirusTotal-ip-45.156.87.69.png) | [AbuseIPDB](./threat-intel/AbuseIPDB-ip-45.156.87.69.png)

**172.82.91.35** — Clean reputation (attacker masquerading)  
[VirusTotal](./threat-intel/VirusTotal-ip-172.82.91.35.png) | [AbuseIPDB](./threat-intel/AbuseIPDB-ip-172.82.91.35.png)

---

## KQL Queries

The full set of Microsoft Sentinel KQL queries used in this investigation is in [`queries/kql_queries.md`](./queries/kql_queries.md). They cover:

- Brute force detection by source IP
- Successful login identification
- CPU anomaly detection
- Firewall change monitoring
- Cron persistence detection
- Full incident timeline aggregation

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|-----|
| Credential Access | Brute Force: Password Guessing | T1110.001 |
| Initial Access | Valid Accounts | T1078 |
| Execution | Scheduled Task/Job: Cron | T1053.003 |
| Persistence | Scheduled Task/Job: Cron | T1053.003 |
| Defense Evasion | Masquerading | T1036 |
| Defense Evasion | Disable or Modify System Firewall | T1562.004 |
| Impact | Resource Hijacking | T1496 |

---

## Incident Report

The full professional incident report following SOC escalation workflows is in [`report/incident_report.md`](./report/incident_report.md).

---

## Repository Structure

```
ssh-honeypot-soc-analysis/
├── README.md                       <- You are here
├── queries/
│   └── kql_queries.md              <- KQL queries for Sentinel
├── report/
│   └── incident_report.md          <- Full incident report
├── Evidence/                       <- SIEM screenshots
│   ├── SIGN_IN_ATTEMPS.webp
│   ├── SUCCESFUL_SIGN_IN.webp
│   ├── CPU_USAGE.webp
│   ├── CRON.webp
│   └── UFW_BLOCK.webp
└── threat-intel/                   <- VirusTotal + AbuseIPDB lookups
    ├── VirusTotal-ip-*.png
    └── AbuseIPDB-ip-*.png
```

---

## Contact

**Tiago Colo Ceppone**  
colotiago8@gmail.com  
[linkedin.com/in/tiago-colo-640057402](https://www.linkedin.com/in/tiago-colo-640057402/)  

Built from a real incident. Documented for learning.

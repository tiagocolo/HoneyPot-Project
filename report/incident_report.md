# Incident Report

**Case ID:** HONEYPOT-2026-001  
**Date:** May 12-13, 2026  
**Classification:** True Positive — CRITICAL  
**Analyst:** Tiago Colo

---

## Summary

An intentionally exposed DigitalOcean droplet (Ubuntu 24.04, SSH port 22 open, weak root password) was compromised within 24 hours. Three independent attackers gained root access via credential stuffing, established persistence through cron, deployed a cryptominer, and modified the firewall to block further access.

---

## Timeline

| Time (UTC-3) | Event |
|--------------|-------|
| May 12 | Automated brute force begins |
| May 13 13:08:31 | First successful root login (92.118.39.236) |
| May 13 13:08:40 | Second successful root login (172.82.91.35) |
| May 13 13:39:59 | Third successful root login (45.156.87.69) |
| May 13 13:40 | Cron persistence installed (/etc/cron.hourly/gcc.sh) |
| May 13 13:45 | CPU usage spikes to 65%+ (cryptomining) |
| May 13 14:00 | UFW firewall modified to block inbound port 22 |

---

## Scope

**Affected Asset:**
- DigitalOcean Droplet — Ubuntu 24.04

**Attack Vector:**
- External — internet-facing SSH service with weak credentials

**Impact:**
- Complete system compromise (root access)
- Cryptomining software deployed (resource hijacking)
- Firewall rules modified
- System used as part of a botnet

---

## Detailed Findings

### 1. Credential Access — Brute Force (T1110.001)

The most aggressive source was 192.227.173.105 with 1,400 failed attempts. Five IPs accounted for 3,858 total attempts.

### 2. Initial Access — Valid Accounts (T1078)

Three IPs successfully authenticated as root. Notably, 172.82.91.35 had a clean reputation on AbuseIPDB and VirusTotal — the attacker likely used it to masquerade as a legitimate user after stealing credentials from 92.118.39.236.

### 3. Persistence — Cron Job (T1053.003)

The attacker created /etc/cron.hourly/gcc.sh — a cron script that executed hourly as root. The filename masquerades as the GNU C Compiler (gcc) binary.

### 4. Defense Evasion — Masquerading (T1036)

The gcc.sh filename was chosen specifically to blend in with legitimate system binaries.

### 5. Defense Evasion — Firewall Modification (T1562.004)

UFW was configured to block inbound connections on port 22, preventing other attackers from accessing the compromised system.

### 6. Impact — Resource Hijacking (T1496)

CPU utilization reached 65.1%, consistent with cryptomining activity. The exact payload was not recovered, but the behavior matches known Linux cryptominers.

---

## Indicators of Compromise

**IPs (Successful Authentication):**
- 92.118.39.236 — Malicious (AbuseIPDB)
- 172.82.91.35 — Clean reputation (masquerading)
- 45.156.87.69 — Malicious (AbuseIPDB)

**IPs (Top Brute Force Sources):**
- 192.227.173.105 — 1,400 attempts
- 167.99.148.102 — 787 attempts
- 192.109.200.78 — 685 attempts
- 45.156.87.253 — 685 attempts
- 159.223.115.49 — 381 attempts

**Files:**
- /etc/cron.hourly/gcc.sh — Malicious cron script (SHA256: not captured)

---

## Recommendations

1. Disable root SSH login (PermitRootLogin no)
2. Enforce SSH key authentication only
3. Implement fail2ban to rate-limit authentication attempts
4. Enable auditd to capture detailed system call logs
5. Deploy EDR agent for endpoint detection and response
6. Monitor for anomalous CPU usage spikes
7. Implement IP reputation blocking at the network perimeter

---

## Report Completed By

**Tiago Colo**  
ISC2 Certified in Cybersecurity (CC)  
colotiago8@gmail.com


# Incident Report

| | |
|---|---|
| **Date opened** | May 12, 2026 |
| **Date escalated** | May 13, 2026 |
| **Severity** | High |
| **Status** | Escalated to L2 |
| **Classification** | True Positive — Active Compromise |
| **Analyst** | L1 SOC — Honeypot Lab |

---

## Summary

A honeypot hosted on DigitalOcean exposed to internet was hit with sustained brute force attacks starting May 12, 2026. On May 13, three IPs successfully authenticated as root. The attacker installed a cryptomining script that persisted via cron, modified UFW to block inbound SSH, and drove CPU to 65.1%. The host became unresponsive. The entire investigation was conducted through Microsoft Sentinel without touching the server.

---

## Timeline

| Time | Event |
|---|---|
| May 12 | Brute force begins across multiple IPs |
| May 12–13 | Attack volume grows — top IP reaches 1,400 attempts |
| May 13, 1:08:31 PM | 92.118.39.236 authenticates as root |
| May 13, 1:39:59 PM | 45.156.87.69 authenticates as root |
| May 13, 1:08:40 PM | 172.82.91.35 authenticates as root with only one attempt|
| May 13, 1:45 PM | /etc/cron.hourly/gcc.sh installed |
| May 13, 2:00 PM | UFW modified — port 22 blocked inbound |
| May 13, 4:27 PM | Cron execution confirmed in Sentinel |
| May 13, 5:00 PM | CPU at 65.1%|
| May 13, 5:12 PM | Escalated to L2 |

---

## Analysis

### Brute Force

From the first two IPs the attack was automated with high volume of attempts and targeting root. The initial attack vector was weak credential security.

### IP (172.82.91.35)

The IP 172.82.91.35 gained access with only one attempt which suggests that the attacker with this IP is the same attacker with 92.118.39.236 IP, I believe this because the IP 92.118.39.236 connected nine seconds before than the IP 172.82.91.35 and since the IP 172.82.91.35 only needed one attempt to sign in I believe that when the IP 92.118.39.236 gained access to the honeypot the threat actor change its IP and authenticated again with the stolen credential. Probably this attacker did this to preserve the IP's clear reputation, that is the reason that caused that when I run the IP 172.82.91.35 in VirusTotal and AbuseIPDB it returned non malicious reports about this IP


### Persistence

The attacker placed `/etc/cron.hourly/gcc.sh` on the system trying to masquerading the cron as the GNU compilator of linux with the name of `gcc` — cron ran it as root every hour.

### Impact

CPU usage climbed steadily after compromise and peaked at 65.1%. with the cron, this is consistent with a probably cryptominer consuming available resources.

### Defense Evasion

Many ufw block events were logged in Sentinel after the compromise, all targeting inbound connections on the host's IP. The attacker locked down port 22 to prevent recovery while maintaining their own access.

---

## IOCs

**Authenticated IPs:**
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

## MITRE ATT&CK

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

## L1 Actions

- Confirmed true positive via Syslog analysis
- Extracted and documented all attacker IPs
- Reconstructed session timeline via KQL
- Identified persistence mechanism by cron
- Identified UFW modification as active defense evasion
- Mapped all findings to MITRE ATT&CK
- Escalated to L2 with full evidence package

---

## Escalation Justification

This went to L2 because root-level access was confirmed active, a persistence mechanism was running, the firewall had been tampered with, and the host was no longer reachable. Forensic analysis of `gcc.sh` and full containment require L2.
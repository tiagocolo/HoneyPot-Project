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
| May 13, 1:08:40 PM | 172.82.91.35 authenticates as root |
| May 13, 1:39:59 PM | 45.156.87.69 authenticates as root |
| May 13, 1:45 PM | /etc/cron.hourly/gcc.sh installed |
| May 13, 2:00 PM | UFW modified — port 22 blocked inbound |
| May 13, 4:27 PM | Cron execution confirmed in Sentinel |
| May 13, 5:00 PM | CPU at 65.1%, host unresponsive |
| May 13, 5:12 PM | Escalated to L2 |

---

## Analysis

### Brute Force

The attack was automated — high volume, multiple sources, all targeting root. No single actor stood out as coordinated; this was opportunistic scanning. The weak password was the only thing that needed to fall, and it did.

### Successful Access

All three IPs that got in had prior failed attempts in the logs. They weren't coming in with known credentials — they found the password through brute force like everyone else, just faster or luckier.

### Persistence

The attacker placed `/etc/cron.hourly/gcc.sh` on the system. Using `gcc` as the filename is a basic masquerading technique — it looks like a compiler binary sitting in a system directory. Cron ran it as root every hour. Sentinel captured the execution pattern but not the script's contents, since `auditd` was not configured.

### Impact

CPU usage climbed steadily after compromise and peaked at 65.1%. Combined with the host becoming unreachable via SSH and web console, this is consistent with a cryptominer consuming available resources.

### Defense Evasion

1,519 UFW BLOCK events were logged in Sentinel after the compromise, all targeting inbound connections on the host's IP. The attacker locked down port 22 to prevent recovery while maintaining their own access.

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
- Identified persistence mechanism and cron execution pattern
- Identified UFW modification as active defense evasion
- Mapped all findings to MITRE ATT&CK
- Escalated to L2 with full evidence package

---

## Escalation Justification

This went to L2 because root-level access was confirmed active, a persistence mechanism was running, the firewall had been tampered with, and the host was no longer reachable. Forensic analysis of `gcc.sh` and full containment require L2 involvement.

---

## Recommendations for L2

1. Power off or snapshot the droplet via DigitalOcean dashboard before anything else
2. Analyze `/etc/cron.hourly/gcc.sh` — identify the miner binary and any C2 infrastructure
3. Check for additional persistence: `.bashrc`, `~/.ssh/authorized_keys`, systemd services
4. Add confirmed attacker IPs to perimeter blocklist
5. Rebuild from clean image — do not attempt to remediate the compromised host
# KQL Queries — Honeypot Investigation

Queries run in Microsoft Sentinel → Logs against the `Syslog` table.

---

## 1 — All IPs with failed SSH attempts

```kql
Syslog
| where TimeGenerated > ago(7d)
| where ProcessName == "sshd"
| where SyslogMessage has "Failed password"
| extend IP = extract(@"from\s+(\d+\.\d+\.\d+\.\d+)", 1, SyslogMessage)
| where isnotempty(IP)
| summarize Attempts = count() by IP
| order by Attempts desc
```

Top results: 192.227.173.105 (1,400), 167.99.148.102 (787), 192.109.200.78 (685)

---

## 2 — IPs that successfully authenticated

```kql
Syslog
| where TimeGenerated > ago(7d)
| where ProcessName == "sshd"
| where SyslogMessage has "Accepted password" or SyslogMessage has "Accepted publickey"
| extend
    IP = extract(@"from\s+(\d+\.\d+\.\d+\.\d+)", 1, SyslogMessage),
    User = extract(@"for\s+(\S+)\s+from", 1, SyslogMessage)
| where isnotempty(IP)
| project TimeGenerated, IP, User, SyslogMessage
| order by TimeGenerated desc
```

Result: 3 IPs authenticated as root on May 14.

---

## 3 — Threat Intelligence correlation

Cross-reference all attacker IPs against Sentinel's built-in TI feeds.

```kql
let IPs = Syslog
| where TimeGenerated > ago(7d)
| where ProcessName == "sshd"
| where SyslogMessage has "Failed password" or SyslogMessage has "Accepted"
| extend IP = extract(@"from\s+(\d+\.\d+\.\d+\.\d+)", 1, SyslogMessage)
| where isnotempty(IP)
| summarize Attempts = count() by IP;
IPs
| join kind=leftouter (
    ThreatIntelligenceIndicator
    | where isnotempty(NetworkIP)
    | summarize by NetworkIP, ThreatType, Description, ConfidenceScore
) on $left.IP == $right.NetworkIP
| project IP, Attempts, ThreatType, ConfidenceScore, Description
| order by Attempts desc
```

---

## 5 — Session timeline for compromising IPs

Full SSH event trace for the three IPs that got in.

```kql
Syslog
| where TimeGenerated > ago(7d)
| where ProcessName == "sshd"
| where SyslogMessage has "45.156.87.69"
    or SyslogMessage has "172.82.91.35"
    or SyslogMessage has "92.118.39.236"
| project TimeGenerated, SyslogMessage
| order by TimeGenerated asc
```

---

## 6 — Post-compromise system activity

All non-SSH events after the initial compromise. This is where the cron job showed up.

```kql
Syslog
| where TimeGenerated > ago(12h)
| where ProcessName != "sshd"
| project TimeGenerated, ProcessName, SyslogMessage
| order by TimeGenerated desc
```

Finding: CRON executing `/etc/cron.hourly/gcc.sh` as root every hour.

---

## 7 — Firewall and defense evasion

Detect changes to UFW, iptables, SSH config, or authorized_keys.

```kql
Syslog
| where TimeGenerated > ago(24h)
| where SyslogMessage has "ufw"
    or SyslogMessage has "iptables"
    or SyslogMessage has "sshd_config"
    or SyslogMessage has "authorized_keys"
| project TimeGenerated, ProcessName, SyslogMessage
| order by TimeGenerated asc
```

Finding: 1,519 UFW BLOCK events — inbound port 22 blocked after compromise.

---

## 8 — Sentinel-generated alerts

```kql
SecurityAlert
| where TimeGenerated > ago(7d)
| project TimeGenerated, AlertName, Severity, Description, Entities, RemediationSteps
| order by TimeGenerated desc
```

---

## Note on visibility gaps

Without `auditd` + `audisp-syslog`, Syslog does not capture commands executed inside SSH sessions. The following cannot be determined from these queries alone:

- Commands run during attacker sessions
- Files accessed, modified, or exfiltrated
- Outbound connections initiated from the host
- Content of `/etc/cron.hourly/gcc.sh`
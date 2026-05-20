# KQL Queries — Honeypot Investigation

Queries run in Microsoft Sentinel → Logs against the `Syslog` table.

---

## 1 — All IPs with failed SSH attempts

```kql
Syslog
| where TimeGenerated > ago(2d)
| where ProcessName == "sshd"
| where SyslogMessage has "Failed password"
| extend IP = extract(@"from\s+(\d+\.\d+\.\d+\.\d+)", 1, SyslogMessage)
| where isnotempty(IP)
| summarize Attempts = count() by IP
| order by Attempts desc
```

Finding: Many IPs were performing a brute force attack

---

## 2 — IPs that successfully authenticated

```kql
Syslog
| where TimeGenerated > ago(2d)
| where ProcessName == "sshd"
| where SyslogMessage has "Accepted password" or SyslogMessage has "Accepted publickey"
| extend
    IP = extract(@"from\s+(\d+\.\d+\.\d+\.\d+)", 1, SyslogMessage),
    User = extract(@"for\s+(\S+)\s+from", 1, SyslogMessage)
| where isnotempty(IP)
| project TimeGenerated, IP, User, SyslogMessage
| order by TimeGenerated desc
```

Finding: 3 IPs authenticated as root on may 13

---

## 3 — Sign in attemps of the authenticated IPs

```kql
Syslog
| where TimeGenerated > ago(7d)
| where ProcessName == "sshd"
| where SyslogMessage has "Failed password"
| extend IP = extract(@"from\s+(\d+\.\d+\.\d+\.\d+)", 1, SyslogMessage)
| where IP in ("45.156.87.69", "172.82.91.35", "92.118.39.236")
| summarize FailedAttempts = count() by IP
| order by FailedAttempts desc
```

Finding: There I see that the IP 172.82.91.35 gain access to the honeypot with only one attempt

---

## 6 — Post-compromise system activity


```kql
Syslog
| where TimeGenerated > ago(2d)
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
| where TimeGenerated > ago(2d)
| where SyslogMessage has "ufw"
    or SyslogMessage has "iptables"
    or SyslogMessage has "sshd_config"
    or SyslogMessage has "authorized_keys"
| project TimeGenerated, ProcessName, SyslogMessage
| order by TimeGenerated asc
```

Finding: many ufw blocks events — inbound port 22 blocked after compromise.



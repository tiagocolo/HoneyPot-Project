# KQL Queries — Microsoft Sentinel

Queries used during the honeypot investigation.

---

## Failed SSH Logins (Brute Force Detection)

```kql
Syslog
| where Facility == "auth"
| where SyslogMessage contains "Failed password for root"
| summarize AttemptCount = count() by SourceIP = tostring(extract("from (\\d+\\.\\d+\\.\\d+\\.\\d+)", 1, SyslogMessage))
| sort by AttemptCount desc
```

## Successful Root Logins

```kql
Syslog
| where Facility == "auth"
| where SyslogMessage contains "Accepted password for root"
| project TimeGenerated, SourceIP = tostring(extract("from (\\d+\\.\\d+\\.\\d+\\.\\d+)", 1, SyslogMessage)), Port = tostring(extract("port (\\d+)", 1, SyslogMessage))
```

## CPU Usage Spike

```kql
Syslog
| where Facility == "user"
| where SyslogMessage contains "CPU"
| project TimeGenerated, SyslogMessage
| sort by TimeGenerated asc
```

## Firewall Changes (UFW)

```kql
Syslog
| where Facility == "user"
| where SyslogMessage contains "UFW"
| project TimeGenerated, SyslogMessage
| sort by TimeGenerated asc
```

## Cron Persistence (gcc.sh)

```kql
Syslog
| where SyslogMessage contains "cron" or SyslogMessage contains "gcc.sh"
| project TimeGenerated, SyslogMessage
| sort by TimeGenerated asc
```

## Full Timeline

```kql
Syslog
| where TimeGenerated between (datetime(2026-05-12 00:00:00) .. datetime(2026-05-14 00:00:00))
| where SyslogMessage contains "Failed password" or SyslogMessage contains "Accepted password" or SyslogMessage contains "gcc.sh" or SyslogMessage contains "UFW" or SyslogMessage contains "CPU"
| project TimeGenerated, SyslogMessage
| sort by TimeGenerated asc
```

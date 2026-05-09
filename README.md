# Azure Sentinel Honeypot SOC Lab

## Overview
This project demonstrates the setup and operation of a cloud-based SOC (Security Operations Center) lab using Microsoft Azure and Microsoft Sentinel.

The lab simulates real-world attack monitoring by deploying a Windows honeypot virtual machine exposed to the internet and ingesting security logs into Microsoft Sentinel for analysis, detection, and investigation.

The project includes:
- Azure VM deployment
- Microsoft Sentinel integration
- Windows Security Event log collection
- KQL threat hunting queries
- Custom analytics detection rules
- Incident generation and investigation
- GeoIP attack mapping visualization
- Threat hunting dashboards

---

# Technologies Used

- Microsoft Azure
- Microsoft Sentinel
- Log Analytics Workspace
- Windows Server / Windows VM
- Kusto Query Language (KQL)
- Azure Network Security Groups (NSGs)
- Remote Desktop Protocol (RDP)

---

# Lab Architecture

Internet Attack Traffic
        ↓
Azure Honeypot VM
        ↓
Windows Security Events
        ↓
Log Analytics Workspace
        ↓
Microsoft Sentinel
        ↓
Detection Rules / Incidents / Dashboards

---

# Objectives

- Build a cloud-hosted SOC lab
- Learn SIEM fundamentals
- Detect brute-force login attempts
- Create custom detection analytics
- Investigate incidents in Sentinel
- Visualize attacker locations using GeoIP mapping
- Practice KQL threat hunting queries

---

# Deployment Steps

## 1. Azure Resource Deployment

Created:
- Resource Group
- Log Analytics Workspace
- Microsoft Sentinel Workspace
- Windows Honeypot VM
- Network Security Group (NSG)

Configured inbound RDP access for honeypot monitoring.

---

## 2. Microsoft Sentinel Configuration

Enabled Microsoft Sentinel on the Log Analytics Workspace.

Installed:
- Windows Security Events connector

Configured:
- Data Collection Rules (DCR)
- AMA agent ingestion

---

## 3. Security Event Log Collection

Collected Windows Security Event logs including:

| Event ID | Description |
|---|---|
| 4624 | Successful Login |
| 4625 | Failed Login |
| 4740 | Account Lockout |

---

# KQL Threat Hunting Queries

## Failed Login Detection

```kusto
SecurityEvent
| where EventID == 4625
| project TimeGenerated, Computer, Account, IpAddress, FailureReason
| sort by TimeGenerated desc
```

## Brute Force Detection 
```kusto
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts=count() by Account, IpAddress
| where FailedAttempts >= 5
| sort by FailedAttempts desc
```

## Successful Login After Failed Attempts
```kusto
SecurityEvent
| where EventID in (4624, 4625)
| summarize
    FailedAttempts = countif(EventID == 4625),
    SuccessfulLogins = countif(EventID == 4624),
    LastSeen = max(TimeGenerated)
    by Account, IpAddress, Computer
| where FailedAttempts >= 5 and SuccessfulLogins >= 1
| sort by FailedAttempts desc
```

## Top Targeted Accounts
```kusto
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts=count() by Account
| sort by FailedAttempts desc
| take 10
```

## Custom Detection Rules
Created scheduled analytics rules for:

- Brute force login detection
- Suspicious successful login detection
- Repeated failed authentication attempts

Configured:

- Incident grouping
- Alert thresholds
- Automatic incident creation

## GeoIP Attack Map

Created a Sentinel workbook to visualize attacker IP locations on a world map using KQL GeoIP enrichment.

This provides geographic visibility into attack sources targeting the honeypot VM.

## Incident Investigation

Investigated Sentinel incidents by:

- Reviewing alerts
- Analyzing source IP addresses
- Examining targeted accounts
- Reviewing attack timelines
- Correlating failed and successful logins

## Key Skills Demonstrated

- SIEM Engineering
- SOC Analysis
- Threat Hunting
- Cloud Security
- KQL Querying
- Incident Response
- Log Analysis
- Microsoft Sentinel
- Azure Administration

## Screenshots

Included in uploads

## Lessons Learned

- How SOC analysts monitor authentication events
- How attackers perform brute-force attacks against exposed RDP services
- How SIEM platforms ingest and correlate security logs
- How to build custom detections using KQL
- How cloud-hosted infrastructure can be monitored and defended

## Future Improvements

- Integrate Microsoft Defender for Endpoint
- Add automated response playbooks
- Deploy Linux honeypot systems
- Integrate threat intelligence feeds
- Add email alerting and automation

## Author

Jack Cundiff
Computer Science Student | Aspiring SOC Analyst / Security Engineer

GitHub:
https://github.com/jackcundiff22

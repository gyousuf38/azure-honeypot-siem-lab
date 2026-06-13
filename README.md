# Azure Honeypot & SIEM Monitoring Lab

## Overview

This project demonstrates the deployment of a cloud-based honeypot and Security Information and Event Management (SIEM) environment using Microsoft Azure and Microsoft Sentinel.

A Windows 10 virtual machine was intentionally exposed to the public Internet to attract unauthorized login attempts. Security events were collected through Azure Monitor Agent, forwarded to a Log Analytics Workspace, analyzed using Kusto Query Language (KQL), enriched with GeoIP intelligence, and visualized through Microsoft Sentinel Workbooks.

The goal of this project was to gain hands-on experience with cloud security monitoring, log analysis, threat detection, and SOC workflows using real-world attack data.

---

## Lab Architecture

<img width="391" height="1003" alt="Architecture Diagram" src="https://github.com/user-attachments/assets/2d6b3877-532e-40eb-b2e2-765ae810dc18" />

### Data Flow

1. Attackers on the public Internet attempted RDP connections against the exposed VM.
2. Failed authentication attempts generated Windows Security Event ID 4625 logs.
3. Azure Monitor Agent collected the logs.
4. Logs were forwarded to a Log Analytics Workspace.
5. Microsoft Sentinel analyzed the events using KQL.
6. GeoIP enrichment mapped source IP addresses to geographic locations.
7. Sentinel Workbooks visualized attack activity through dashboards and maps.

---

## Technologies Used

* Microsoft Azure
* Azure Virtual Machines
* Azure Virtual Networks (VNet)
* Network Security Groups (NSG)
* Azure Monitor Agent (AMA)
* Log Analytics Workspace
* Microsoft Sentinel
* Kusto Query Language (KQL)
* Windows Event Viewer
* GeoIP Watchlists
* Sentinel Workbooks

---

## Results

* Successfully deployed and monitored a publicly exposed Windows 10 honeypot.
* Collected and analyzed 20,000+ failed RDP authentication attempts.
* Observed automated brute-force attacks targeting common usernames such as:

  * Administrator
  * Admin
  * Administrador
  * Backup
  * User
  * Test
* Identified attack traffic originating from multiple countries.
* Built dashboards and visualizations using Microsoft Sentinel Workbooks.

---

## Key Findings

### Publicly Exposed Services Are Discovered Quickly

Within hours of exposing TCP port 3389, the honeypot began receiving automated login attempts from Internet scanners and brute-force tools.

### Common Username Enumeration

Attackers repeatedly attempted logins using common administrative accounts such as:

* Administrator
* Administrador
* Admin
* Backup
* User
* Operator

### Global Attack Sources

GeoIP enrichment revealed attack traffic originating from multiple geographic regions including Europe, Asia, North America, and Australia.

---

## Investigation & Analysis

### Failed Logon Monitoring (Event ID 4625)

Event ID 4625 indicates a failed authentication attempt and served as the primary indicator for identifying brute-force activity.

<img width="2027" height="1121" alt="Failed Logon Events" src="https://github.com/user-attachments/assets/50a7868d-94a3-41ce-b2e6-ecdb13fa5998" />

---

### Attack Origin Mapping

Microsoft Sentinel Workbooks were used to visualize attack sources globally after GeoIP enrichment.

<img width="1145" height="514" alt="Attack Map" src="https://github.com/user-attachments/assets/db2d77b1-7758-494f-ad67-ca891470772e" />

---

### Most Common Usernames Targeted

The following usernames were among the most frequently targeted during brute-force attempts.

<img width="567" height="1071" alt="Top Usernames" src="https://github.com/user-attachments/assets/338ab020-ae25-43f1-bd76-5d22b9367e18" />

---

### Top Source IP Addresses

Repeated failed authentication attempts were traced to a small number of highly active source IP addresses.

<img width="534" height="650" alt="image" src="https://github.com/user-attachments/assets/92c231a2-08be-4ae7-88ea-13fb28498f5b" />

---

## Sample KQL Queries

### Failed Logon Events

```kusto
SecurityEvent
| where EventID == 4625
| project TimeGenerated, Account, Computer, EventID, Activity, IpAddress
| order by TimeGenerated desc
```

### Top Attacking Usernames

```kusto
SecurityEvent
| where EventID == 4625
| summarize Attempts=count() by Account
| order by Attempts desc
```

### Top Source IP Addresses

```kusto
SecurityEvent
| where EventID == 4625
| summarize Attempts=count() by IpAddress
| order by Attempts desc
```

### Failed Logons Over Time

```kusto
SecurityEvent
| where EventID == 4625
| summarize Attempts=count() by bin(TimeGenerated, 1h)
| render timechart
```

---

## Lessons Learned

* Publicly exposed RDP services are rapidly discovered by automated scanners.
* SIEM platforms provide centralized visibility into authentication activity.
* KQL enables efficient investigation of large security datasets.
* GeoIP enrichment adds valuable context during threat investigations.
* Microsoft Sentinel can collect, analyze, enrich, and visualize security telemetry at scale.

---

## Disclaimer

This project was performed in a controlled educational environment for cybersecurity learning purposes. No production systems, personal accounts, or sensitive resources were connected to the honeypot environment.

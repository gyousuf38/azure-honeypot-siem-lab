# Azure Honeypot & SIEM Monitoring Lab

## Overview

This project demonstrates the deployment of a cloud-based honeypot and Security Information and Event Management (SIEM) environment using Microsoft Azure and Microsoft Sentinel.

A Windows 10 virtual machine was intentionally exposed to the public Internet to attract unauthorized login attempts. Security events were collected through Azure Monitor Agent, forwarded to a Log Analytics Workspace, analyzed using Kusto Query Language (KQL), enriched with GeoIP intelligence, and visualized through Microsoft Sentinel Workbooks.

The goal of this project was to gain hands-on experience with cloud security monitoring, log analysis, threat detection, and SOC workflows using real-world attack data.

---

## Lab Architecture

<img width="462" height="1067" alt="image" src="https://github.com/user-attachments/assets/ef24b430-529b-410f-8456-0ef30dd77440" />

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

<img width="1180" height="1072" alt="image" src="https://github.com/user-attachments/assets/186d73e8-005b-4568-ad63-89ff914cf11a" />

---

### Attack Origin Mapping

Microsoft Sentinel Workbooks were used to visualize attack sources globally after GeoIP enrichment.

<img width="1192" height="543" alt="image" src="https://github.com/user-attachments/assets/4fff904b-e9b4-49f3-8486-9bfc9a2b8862" />

---

### Most Common Usernames Targeted

The following usernames were among the most frequently targeted during brute-force attempts.

<img width="549" height="1073" alt="image" src="https://github.com/user-attachments/assets/d1dfd19e-6e48-4b64-b72f-19560b2aea9d" />

---

### Top Source IP Addresses

Repeated failed authentication attempts were traced to a small number of highly active source IP addresses.

<img width="575" height="695" alt="image" src="https://github.com/user-attachments/assets/ca889fe0-3760-445b-9ece-f8b39154da4a" />

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

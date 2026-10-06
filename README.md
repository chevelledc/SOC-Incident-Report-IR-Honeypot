<img width="1024" height="500" alt="image" src="https://github.com/user-attachments/assets/9d743403-333e-48e1-9af6-0406365d5fea" />


# Incident Report: Data Destruction & Extortion on FINANCE-SRV03 (MySQL)

**Incident ID:** `IR-2026-0910-FINANCE-SRV03`  
**Severity:** High  
**Classification:** Data Destruction / Extortion (Opportunistic MySQL Ransom Campaign)  
**Affected Asset:** `FINANCE-SRV03` (Azure-hosted Windows Server running MySQL 8.0)  
**Prepared By:** Chevelle Gauis Dela Cruz
**Report Date:** 2026-09-11  

---

## Summary

On **September 8, 2026, between 20:24 and 20:27**, internet-facing MySQL 8.0 instance hosted on `FINANCE-SRV03` was brute-forced and compromised. 

The threat actor executed the following actions:
1. **Data Enumeration & Staging:** Enumerated the `credentials` table (`customer_id`, `username`, `password`, `role`) within the `cr_corp_01` database and dumped its contents.
2. **Data Destruction:** Dropped three databases (`cr_corp_01`, `sakila`, `world`).
3. **Privilege Revocation:** Stripped administrative DDL/DML privileges from the `root` account to thwart immediate local recovery.
4. **Extortion Note:** Created a ransom table (`RECOVER_YOUR_DATA.recover_your_data`) demanding **0.0108 BTC** with a 48-hour deadline.

<img width="1342" height="117" alt="image" src="https://github.com/user-attachments/assets/106afdba-fc9b-4c80-9a48-43ff290c51b0" />

**Key Telemetry Findings:**
- No host-level malware, web shells, or persistence mechanisms were detected in the reviewed Windows telemetry (`DeviceProcessEvents`, `DeviceRegistryEvents`, `DeviceFileEvents`).
- The compromise appears confined strictly to the database layer.
  
---

## Incident Details & Impact Assessment
| Parameter | Details |
| :--- | :--- |
| **Impacted Services** | Applications relying on database `cr_corp_01` (Corporate / Customer-facing application) |
| **Impacted Data** | `cr_corp_01` (Organization/Customer data), `sakila` & `world` (MySQL sample schemas) |

### Impact Breakdown

* **Confidentiality:** **HIGH RISK**  
  The `credentials` table (`cred_id`, `customer_id`, `username`, `password`, `role`, `last_login`) was explicitly queried and dumped via `SELECT` queries immediately prior to database deletion. Off-host exfiltration cannot be verified due to missing network layer telemetry.
* **Integrity & Availability:** **CRITICAL**  
  Three databases were dropped (9 tables and foreign key constraints explicitly purged). Revocation of `root`'s `INSERT`, `UPDATE`, `DELETE`, `DROP`, and `CREATE` privileges blocked standard local administrative recovery workflows.
* **Business Impact:**  
  Service outage for core applications backed by `cr_corp_01`. Potential regulatory breach notification obligations if customer credentials were stored in cleartext or weak hashes (column data non-visible in audit logs).

---

## Threat Intelligence & Indicators of Compromise (IOCs)

| IOC Type | Value | Source | Notes / Description |
| :--- | :--- | :--- | :--- |
| **BTC Address** | `bc1q0l7hr5v220f5qlqhjhg4p3jjqfkgudazzjnlkw` | `MySqlAudit_Queries` | Payment demand: 0.0108 BTC (~48hr deadline) |
| **Contact Email** | `ak+2mrn@onionmail.org` | `MySqlAudit_Queries` | Attacker contact communication |
| **Reference URL** | `hxxps://spoo[.]me/mysql1` | `MySqlAudit_Queries` | Shortener link (unresolved/unvalidated) |
| **DATAID** | `2MRN` | `MySqlAudit_Queries` | Campaign identifier |
| **Ransom Table** | `RECOVER_YOUR_DATA.recover_your_data` | `MySqlAudit_Queries` | Created `2026-09-08 20:26:58` |
| **Source IP (DB Initial Attack)** | `64.89.163.152`, `64.89.163.92` | `MySqlAudit_CL-AuthLogs` | Failed root logons prior to compromise window |
| **Source IP (RDP Brute Force)** | `37.27.141.182` | `DeviceLogonEvents` | 24 failed `administrator` logons (Sep 8) |

---

## Forensic Timeline
| Time (Log-Local) | Artifact Source | Event Description |
| :--- | :--- | :--- |
| **Sep 8, 17:03–20:30** | `DeviceLogonEvents` | 24 failed RDP authentication attempts for `administrator` from `37.27.141.182`. |
| **Sep 8, 18:49–20:24** | `MySqlAudit_CL-AuthLogs` | Multiple failed MySQL `root` logons from `64.89.163.152` and `64.89.163.92`. |
| **Sep 8, 20:24:33–20:24:52** | `MySqlAudit_Queries` | Authenticated MySQL session (connections 22–24) enumerates `cr_corp_01`.`credentials` schema and dumps full column set (`cred_id, customer_id, username, password, role, last_login`). |
| **Sep 8, 20:24:53–20:27:01** | `MySqlAudit_Queries` | Destructive sequence runs per-database: `cr_corp_01` tables dropped (incl. `credentials`) at 20:24:53–54; `sakila` tables dropped at 20:26:40–41; `world` tables dropped and all three `DROP DATABASE` statements fire at 20:26:56–58; `RECOVER_YOUR_DATA` created and ransom note inserted; `root`@`'%'` revoked at 20:27:01. |

---
## MITRE ATT&CK Mapping
| Behavior | ATT&CK |
| --- | --- |
| Public scanning on ports `3306` and `3389` | `T1595.001` — Active Scanning: IP Blocks |
| Connecting to exposed MySQL service | `T1190` — Exploit Public-Facing Application |
| RDP brute force | `T1110` — Brute Force |
| Remote access using exposed/default account | `T1078.001` — Valid Accounts: Default Accounts |
| Database information collection | `T1213` — Data from Information Repositories |
| Privilege discovery | `T1069` — Permission Groups Discovery |
| Suspected automated collection | `T1119` — Automated Collection |
| Table deletion | `T1485` — Data Destruction |
| Ransom/extortion artifact | `T1491.001` — Internal Defacement |

---

## Incident Root Cause and Threat Analysis

1. **Primary Attack Vector (High Confidence):**  
   The root enabler of the incident was the direct exposure of the MySQL database service (TCP port 3306) to the public internet, paired with weak or blank default credentials on the <code>root</code> account. Telemetry indicates the compromise was driven by opportunistic, automated scanning scripts that systematically tested standard administrative accounts (such as <code>admin</code>, <code>sa</code>, and <code>root</code>) until gaining access, rather than a targeted intrusion.
2. **Telemetry Gap:**  
   The precise authentication log event corresponding to the successful initial connection (connections 22–24) on Sep 8 was missing from `MySqlAudit_CL-AuthLogs.csv`, though preceding failed attempts and immediate subsequent query logs confirm successful compromise.
3. **RDP Exposure:**  
   TCP port `3389` was publicly exposed, attracting concurrent brute-force campaigns. No operational link was identified between host-level RDP attempts and the MySQL database destruction.

---
## Mitigation & Response Actions

<div style="text-align: justify;">

### 1.<strong> Immediate Containment</strong><br>
  Following the discovery of the incident, immediate containment measures were executed to isolate the system and prevent further unauthorized access. Inbound traffic to TCP ports <code>3306</code> (MySQL) and <code>3389</code> (RDP) was restricted at the Azure Network Security Group (NSG) and firewall layer, enforcing exclusive administrative access through VPN and Bastion paths. Additionally, credentials for the MySQL <code>root</code> account, local Windows administrative accounts, and application connection strings were immediately cycled and hardened. Complete disk and memory forensic snapshots of <code>FINANCE-SRV03</code> were captured to preserve artifacts prior to any host modifications or rebuilding.
<br>
### 2.<strong> Eradication & Recovery</strong><br>
  Eradication and system recovery proceeded once containment was established. The MySQL instance was re-provisioned from a clean, hardened base image, deliberately excluding all extortion artifacts created by the threat actor. The <code>cr_corp_01</code> database was restored from the most recent verified pre-incident backup predating September 8 at 20:24, with full schema and data integrity validated prior to returning the database to production. Finally, a thorough audit of all local database users and OS accounts was conducted, purging unauthorized permissions established during the attack window.

</div>

## KQL Threat Hunting Queries

### 1. Scope Analysis: Was the credentials table accessed before destruction?
```kql
MySQLAudit_CL
| where TimeGenerated between (datetime(2026-09-08 12:00:00) .. datetime(2026-09-08 12:30:00))
| where RawData has "Query"
| extend RawData = replace_string(RawData, "\t", " ")
| extend Query = split(RawData, "Query")[1]
| where Query has "credentials"
| project TimeGenerated, Query, RawData
```
<img width="1475" height="400" alt="image" src="https://github.com/user-attachments/assets/8e01f483-2b30-47af-b9ed-68adf56f3448" />


### 2. Reconstruct the destructive sequence
```kql
MySQLAudit_CL
| where RawData has "Query"
| extend RawData = replace_string(RawData, "\t", " ")
| extend DeviceName = tostring(split(_ResourceId, "/")[-1])
| where DeviceName == "finance-srv03"
| extend Query = split(RawData, "Query")[1]
| where Query has_any ("DROP DATABASE", "DROP TABLE", "CREATE DATABASE", "RECOVER_YOUR_DATA", "REVOKE")
| project TimeGenerated, Query
| order by TimeGenerated asc
```
<img width="1567" height="546" alt="image" src="https://github.com/user-attachments/assets/0523bcca-2b30-48ab-96db-88ad2bac48e7" />


---

## Conclusion & Final Scope

<div style="text-align: justify;">

The investigation confirmed that the MySQL service was compromised. Utilizing remote access through the <code>root</code> account, the threat actor performed schema enumeration, dumped the sensitive <code>credentials</code> table, dropped three databases (<code>cr_corp_01</code>, <code>sakila</code>, <code>world</code>), revoked administrative privileges from <code>root</code>, and created a ransom table demanding 0.0108 BTC.

On the other hand, while the Windows host experienced significant RDP brute-force activity, there is no confirmed evidence of successful host-level compromise, malware execution, or persistence mechanisms resulting from those attempts.

To conclude, confirmed compromise of the MySQL database resulting in data destruction and extortion. No confirmed evidence of Windows host-level compromise, and off-host data exfiltration remains unconfirmed due to a lack of network layer telemetry.

</div>

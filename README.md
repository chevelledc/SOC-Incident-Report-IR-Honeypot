# FINANCE-SRV03 — MySQL Data Destruction & Extortion Investigation

<p align="center">
  <img width="1024" height="500" alt="FINANCE-SRV03 MySQL incident investigation" src="https://github.com/user-attachments/assets/9d743403-333e-48e1-9af6-0406365d5fea" />
</p>


## 📌 Project Overview

This project documents the investigation of a simulated high-severity security incident involving an internet-facing MySQL 8.0 service hosted on an Azure Windows Server.

The investigation identified suspicious authentication activity, access to a database containing credential-related fields, destructive SQL operations, administrative privilege revocation, and the creation of a ransom table demanding payment.

Using MySQL audit logs, KQL queries, and Microsoft Defender for Endpoint telemetry, I reconstructed the database attack sequence, assessed the scope of compromise, reviewed potential indicators of compromise (IOCs), and documented containment and recovery actions.

**Incident ID:** `IR-2026-0910-FINANCE-SRV03`  
**Severity:** High  
**Classification:** Data Destruction / Extortion  
**Affected Host:** `FINANCE-SRV03`  
**Incident Date:** September 8, 2026  
**Environment:** Azure Windows Server / MySQL 8.0  
**Tools:** Microsoft Sentinel, Log Analytics, KQL, Microsoft Defender for Endpoint, MySQL Audit Logs

**Timezone:** All timestamps in this report use UTC, consistent with the Azure Log Analytics `TimeGenerated` values used in the KQL queries.

---

## 🔍 Investigation Workflow

```text
Authentication Log Review
          ↓
Suspicious MySQL Activity Identification
          ↓
Database Query Investigation
          ↓
Destructive SQL Sequence Reconstruction
          ↓
IOC Extraction & Threat Analysis
          ↓
Windows Endpoint Telemetry Review
          ↓
Impact Assessment & Incident Response
```

---

## 🚨 Incident Summary

On September 8, 2026, the MySQL service on `FINANCE-SRV03` was compromised following suspicious remote authentication activity.

The investigation found that the attacker accessed the `cr_corp_01` database and queried its `credentials` table before performing destructive database operations. Three databases were dropped, administrative privileges were revoked from the remote `root` account, and a ransom table was created containing a demand for 0.0108 BTC within 48 hours.

Concurrent RDP brute-force attempts were also identified against the Windows `administrator` account. However, the available evidence did not establish a successful Windows host compromise or a direct connection between the RDP activity and the MySQL attack.

The investigation confirmed database compromise, destructive SQL activity, and extortion. Off-host data exfiltration could not be verified because network-layer telemetry was unavailable.

---

## 📝 Ransom Note

During the investigation, the `RECOVER_YOUR_DATA.recover_your_data` table was identified in MySQL. The table contained an extortion message demanding 0.0108 BTC within 48 hours and threatening to publicly disclose and delete the victim's data.

<p align="center">
  <img width="1917" height="1077" alt="MYSQL Breached" src="https://github.com/user-attachments/assets/b0e279f7-ef91-4407-a077-b90800bb7387" />
</p>

### Ransom Note Details

| Field | Details |
|---|---|
| Database | `RECOVER_YOUR_DATA` |
| Table | `recover_your_data` |
| Bitcoin Demand | `0.0108 BTC` |
| Deadline | 48 hours |
| Bitcoin Address | `bc1q0l7hr5v220f5qlqhjhg4p3jjqfkgudazzjnlkw` |
| Contact Email | `ak+2mrn@onionmail.org` |
| Reference URL | `hxxps://spoo[.]me/mysql1` |
| Data Identifier | `2MRN` |
| Creation Time (UTC) | September 8, 2026, 12:26:58 UTC |

The ransom note provided evidence of extortion following the destructive database activity. Its claim that the data had been backed up by the attacker was not independently verified.

---

## 🧩 Key Findings

| Finding | Evidence | Assessment |
|---|---|---|
| MySQL authentication attempts | Failed `root` logons from `64.89.163.152` and `64.89.163.92` | Confirmed |
| RDP brute-force activity | 24 failed `administrator` logons from `37.27.141.182` | Confirmed |
| Credential-table access | Queries against `cr_corp_01.credentials` | Confirmed |
| Database destruction | `cr_corp_01`, `sakila`, and `world` were dropped | Confirmed |
| Administrative privilege revocation | Privileges revoked from `root`@`'%'` | Confirmed |
| Ransom artifact | `RECOVER_YOUR_DATA.recover_your_data` created | Confirmed |
| Windows host-level compromise | No host-level malware or persistence detected in reviewed telemetry | Not confirmed |
| Data exfiltration | No network-layer evidence available to verify transfer | Unconfirmed |
| Successful authentication event | Corresponding event missing from the reviewed authentication log export | Telemetry gap |

---

## 🕒 Incident Timeline

All timestamps below are presented in **UTC**.

| Date and Time (UTC) | Event |
|---|---|
| September 8, 09:03–12:30 | 24 failed RDP authentication attempts against `administrator` from `37.27.141.182` |
| September 8, 10:49–12:24 | Failed MySQL `root` logons from `64.89.163.152` and `64.89.163.92` |
| September 8, 12:24:33–12:24:52 | Connections 22–24 queried and enumerated `cr_corp_01.credentials` |
| September 8, 12:24:53–12:24:54 | Tables in `cr_corp_01`, including `credentials`, were dropped |
| September 8, 12:26:40–12:26:41 | Tables in `sakila` were dropped |
| September 8, 12:26:56–12:26:58 | Tables in `world` were dropped and database deletion operations were executed |
| September 8, 12:26:58 | Ransom table created and extortion message inserted |
| September 8, 12:27:01 | Administrative privileges revoked from `root`@`'%'` |

---

## 🧪 KQL Threat Hunting

### 1. Investigating Access to the Credentials Table

The first query filters MySQL audit records for queries referencing the `credentials` table during the incident window.

**Query window:** September 8, 12:00–12:30 UTC.

```kql
MySQLAudit_CL
| where TimeGenerated between (datetime(2026-09-08 12:00:00) .. datetime(2026-09-08 12:30:00))
| where RawData has "Query"
| extend RawData = replace_string(RawData, "\t", " ")
| extend Query = split(RawData, "Query")[1]
| where Query has "credentials"
| project TimeGenerated, Query, RawData
```

<img width="1475" height="400" alt="KQL query identifying access to the credentials table" src="https://github.com/user-attachments/assets/8e01f483-2b30-47af-b9ed-68adf56f3448" />

**Finding:** The audit records identified queries referencing `cr_corp_01.credentials` before the destructive activity. The table contained fields associated with customer identities and credentials, including `username`, `password`, `role`, and `last_login`.

This supports the conclusion that the table was queried. It does not independently establish whether the data was successfully transmitted outside the environment.

### 2. Reconstructing the Destructive SQL Sequence

The second query identifies database and table deletion, database creation, ransom-related activity, and privilege revocation.

```kql
MySQLAudit_CL
| where RawData has "Query"
| extend RawData = replace_string(RawData, "\t", " ")
| extend DeviceName = tostring(split(_ResourceId, "/")[-1])
| where DeviceName == "finance-srv03"
| extend Query = split(RawData, "Query")[1]
| where Query has_any (
    "DROP DATABASE",
    "DROP TABLE",
    "CREATE DATABASE",
    "RECOVER_YOUR_DATA",
    "REVOKE"
)
| project TimeGenerated, Query
| order by TimeGenerated asc
```

<img width="1567" height="546" alt="KQL query identifying destructive SQL operations" src="https://github.com/user-attachments/assets/0523bcca-2b30-48ab-96db-88ad2bac48e7" />

**Finding:** The query was used to reconstruct the order of destructive SQL activity, including database/table deletion, creation of the ransom-related artifact, and privilege revocation.

This helped establish that the incident progressed beyond failed authentication attempts into a database session performing destructive operations.

### 3. Windows Endpoint Telemetry Review

The investigation reviewed Microsoft Defender for Endpoint telemetry, including:

- `DeviceProcessEvents`
- `DeviceRegistryEvents`
- `DeviceFileEvents`
- `DeviceLogonEvents`

**Finding:** No host-level malware, web shells, or persistence mechanisms were detected in the reviewed process, registry, and file telemetry. Repeated failed RDP authentication attempts were also identified.

These findings do not prove that the Windows host was never compromised. They indicate that the available endpoint telemetry did not confirm a successful host-level compromise.

---

## 💥 Impact Assessment

| Impact Area | Assessment | Details |
|---|---|---|
| Confidentiality | High risk | The `credentials` table was queried; off-host exfiltration remains unverified |
| Integrity | Critical | Three databases were dropped |
| Availability | Critical | Applications relying on `cr_corp_01` were affected by database destruction |
| Administrative recovery | High impact | Administrative privileges were revoked from the remote `root` account |
| Regulatory exposure | Potential | Obligations depend on the actual data involved and applicable requirements |

### Affected Databases

- `cr_corp_01` — corporate/customer application database
- `sakila` — MySQL sample database
- `world` — MySQL sample database

The `credentials` table contained the following fields:

`cred_id`, `customer_id`, `username`, `password`, `role`, `last_login`

The audit evidence showed queries and column references, but did not establish the underlying credential values or whether passwords were stored in plaintext or securely hashed.

---

## 🕵️ Indicators of Compromise (IOCs)

| IOC Type | Value | Context |
|---|---|---|
| Bitcoin address | `bc1q0l7hr5v220f5qlqhjhg4p3jjqfkgudazzjnlkw` | Payment demand of 0.0108 BTC |
| Contact email | `ak+2mrn@onionmail.org` | Contact information in ransom artifact |
| Reference URL | `hxxps://spoo[.]me/mysql1` | Reference included in ransom artifact; not independently validated |
| Campaign identifier | `2MRN` | Identifier in ransom artifact |
| Ransom table | `RECOVER_YOUR_DATA.recover_your_data` | Created September 8, 2026, at 12:26:58 UTC |
| MySQL source IP | `64.89.163.152` | Failed `root` authentication attempts |
| MySQL source IP | `64.89.163.92` | Failed `root` authentication attempts |
| RDP source IP | `37.27.141.182` | Failed `administrator` authentication attempts |

*These indicators are associated with the observed incident and are not, by themselves, proof of attribution to a specific threat actor.*

---

## 🎯 MITRE ATT&CK Mapping

| Observed Behavior | ATT&CK Technique |
|---|---|
| Repeated failed MySQL and RDP authentication attempts | `T1110` — Brute Force |
| Exploitation of an exposed MySQL service, if exploitation is confirmed | `T1190` — Exploit Public-Facing Application |
| Queries against the database's credentials table | `T1213` — Data from Information Repositories |
| Destruction of databases and tables | `T1485` — Data Destruction |
| Creation of a ransom table containing an extortion message | `T1491.001` — Defacement:Internal Defacement |

---

## 🧠 Root Cause Analysis

### Primary Attack Vector

The primary security weakness was the public exposure of MySQL on TCP port `3306`, combined with weak or blank default credentials for the `root` account.

The investigation identified repeated failed authentication attempts followed by database query activity consistent with successful access. The successful authentication event itself was missing from the reviewed authentication log export, limiting the reconstruction of the precise login event.

### Concurrent RDP Activity

TCP port `3389` was also exposed and received repeated failed authentication attempts against the Windows `administrator` account.

The investigation did not establish a direct connection between the RDP activity and the MySQL database destruction. The RDP activity should therefore be treated as a separate observed attack surface unless additional evidence establishes a relationship.

### Contributing Factors

- MySQL was reachable from the public internet.
- The remote database administrator account was insufficiently protected.
- Remote administrative services were exposed.
- Authentication telemetry was incomplete.
- Network-layer telemetry was unavailable to verify potential data exfiltration.

---

## 🛡️ Incident Response & Remediation

### 1. Containment

- Restricted inbound TCP ports `3306` and `3389` through the Azure Network Security Group and firewall.
- Limited administrative access to VPN and Azure Bastion paths.
- Rotated and hardened database and Windows administrative credentials.
- Captured disk and memory forensic snapshots before rebuilding the affected host.

### 2. Eradication and Recovery

- Re-provisioned the MySQL environment from a clean, hardened base image.
- Removed attacker-created extortion artifacts from the rebuilt environment.
- Restored `cr_corp_01` from a verified pre-incident backup predating September 8, 2026, at 12:24 UTC.
- Validated restored schema and data integrity before returning the database to service.
- Audited database users, privileges, and Windows accounts for unauthorized changes.

### 3. Recommended Preventive Controls

- Keep MySQL off the public internet wherever possible.
- Disable remote `root` login and enforce strong, unique credentials.
- Apply least-privilege permissions to database accounts.
- Alert on successful MySQL authentication from unexpected IP addresses.
- Detect destructive SQL statements, including `DROP DATABASE`, `DROP TABLE`, and mass deletion operations.
- Monitor for suspicious ransom-related database names and extortion messages.
- Correlate failed logons with subsequent successful sessions and destructive SQL operations.
- Retain authentication, database audit, endpoint, and network telemetry.
- Regularly test database restoration and maintain protected, offline or immutable backups.

---

## 📚 Lessons Learned

This investigation demonstrated the importance of correlating authentication events, database audit logs, and endpoint telemetry to reconstruct an incident.

The key finding was the sequence of database reconnaissance, credential-table access, destructive SQL activity, privilege revocation, and extortion within a short time window.

The investigation also highlighted a critical forensic distinction: **evidence of data access is not the same as evidence of successful data exfiltration.** The available logs supported the conclusion that the credentials table was queried, but the lack of network-layer evidence prevented confirmation that data left the environment.

**Skills demonstrated:** MySQL audit log analysis, KQL threat hunting, Microsoft Defender for Endpoint telemetry review, Azure security, IOC extraction, MITRE ATT&CK mapping, impact assessment, incident reconstruction, and incident response.

---

## 🏁 Final Assessment

The investigation confirmed a MySQL database compromise involving access to `cr_corp_01.credentials`, destruction of three databases, administrative privilege revocation, and the creation of a ransom artifact demanding 0.0108 BTC.

Concurrent RDP brute-force activity was confirmed, but successful Windows host compromise was not established. Off-host data exfiltration also remained unconfirmed because network-layer evidence was unavailable.

**Final scope:** Confirmed MySQL compromise involving sensitive-table access, data destruction, privilege revocation, and extortion. No confirmed Windows host-level compromise or off-host data exfiltration.

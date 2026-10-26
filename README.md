# FINANCE-SRV03 — MySQL Data Destruction & Extortion Investigation

<p align="center">
  <img width="1024" height="500" alt="FINANCE-SRV03 MySQL incident investigation" src="https://github.com/user-attachments/assets/9d743403-333e-48e1-9af6-0406365d5fea" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Azure-Windows%20Server-0089D6" alt="Azure Windows Server" />
  <img src="https://img.shields.io/badge/MySQL-8.0-4479A1" alt="MySQL 8.0" />
  <img src="https://img.shields.io/badge/Microsoft-Defender%20for%20Endpoint-0078D4" alt="Microsoft Defender for Endpoint" />
  <img src="https://img.shields.io/badge/KQL-Threat%20Hunting-informational" alt="KQL Threat Hunting" />
  <img src="https://img.shields.io/badge/MITRE-ATT%26CK-red" alt="MITRE ATT&CK" />
  <img src="https://img.shields.io/badge/Severity-High-orange" alt="High Severity" />
</p>

> **Quick summary:** Investigated a high-severity incident involving the compromise of an internet-facing MySQL 8.0 service on `FINANCE-SRV03`. The attacker accessed the database using the `root` account, enumerated and queried a sensitive credentials table, dropped three databases, revoked administrative privileges, and created a ransom table demanding 0.0108 BTC. Reviewed Windows endpoint telemetry did not establish host-level compromise, and off-host data exfiltration could not be verified.

---

## 🧪 Investigation Overview

This investigation documents the analysis of a database compromise, the reconstruction of destructive SQL activity, the assessment of business impact, and the response actions taken to contain and recover the affected system.

- **Incident ID:** `IR-2026-0910-FINANCE-SRV03`
- **Severity:** High
- **Classification:** Data Destruction / Extortion
- **Affected asset:** `FINANCE-SRV03`
- **Environment:** Azure-hosted Windows Server running MySQL 8.0
- **Incident date:** September 8, 2026
- **Investigation focus:** MySQL audit logs, Windows authentication events, endpoint telemetry, and KQL threat hunting
- **Prepared by:** Chevelle Gauis Dela Cruz

### Investigation workflow

```text
Review Authentication Logs
          ↓
Identify Suspicious MySQL Access
          ↓
Reconstruct SQL Query Activity
          ↓
Confirm Credential Table Access
          ↓
Identify Database Destruction
          ↓
Analyze Ransom Artifacts & IOCs
          ↓
Assess Host Compromise & Impact
          ↓
Containment, Eradication & Recovery
```

---

## 🚨 What Happened

On September 8, 2026, between approximately 20:24 and 20:27 log-local time, the exposed MySQL service on `FINANCE-SRV03` was compromised.

The investigation reconstructed the following attack sequence:

1. **Brute-force activity:** Repeated failed MySQL `root` authentication attempts preceded the compromise. Concurrent RDP brute-force attempts targeted the Windows `administrator` account.
2. **Database reconnaissance:** The attacker enumerated the `cr_corp_01` database and accessed its `credentials` table.
3. **Credential data access:** SQL queries retrieved the table's column set, including `username`, `password`, and other customer-related fields, before the database was destroyed.
4. **Database destruction:** The attacker dropped three databases: `cr_corp_01`, `sakila`, and `world`.
5. **Privilege revocation:** Administrative DDL/DML privileges were revoked from the remote `root` account, interfering with standard administrative recovery.
6. **Extortion:** A ransom table was created containing a payment demand of 0.0108 BTC and a 48-hour deadline.

The confirmed database attack chain was:

```text
Publicly Exposed MySQL (TCP/3306)
              ↓
Repeated Failed Root Logons
              ↓
Successful Remote Database Access
              ↓
Schema Enumeration & Credential Queries
              ↓
Three Databases Dropped
              ↓
Root Administrative Privileges Revoked
              ↓
Ransom Table & Extortion Message Created
```

**Confirmed scope:** MySQL database compromise, credential-table access, destructive SQL activity, and extortion.

**Unconfirmed scope:** Off-host data exfiltration and successful Windows host compromise.

---

## 🔍 Key Findings

| Finding | Evidence | Assessment |
|---|---|---|
| MySQL brute-force activity | Failed `root` logons from `64.89.163.152` and `64.89.163.92` | Confirmed |
| RDP brute-force activity | 24 failed `administrator` logons from `37.27.141.182` | Confirmed |
| Credential-table access | Queries against `cr_corp_01.credentials` before destruction | Confirmed |
| Database destruction | Three databases dropped, with associated tables and constraints purged | Confirmed |
| Administrative privilege revocation | Privileges revoked from `root`@`'%'` | Confirmed |
| Ransom artifact | `RECOVER_YOUR_DATA.recover_your_data` created with a payment demand | Confirmed |
| Host-level malware or persistence | No evidence detected in the reviewed Windows telemetry | Not detected |
| Off-host data exfiltration | No network-layer telemetry available to verify transfer | Unconfirmed |
| Exact successful authentication event | Corresponding event missing from the reviewed authentication log export | Telemetry gap |

---

## 🕒 Forensic Timeline

All times below are reported in the incident report's log-local time.

| Time — September 8, 2026 | Event |
|---|---|
| 17:03–20:30 | 24 failed RDP authentication attempts against `administrator` from `37.27.141.182` |
| 18:49–20:24 | Multiple failed MySQL `root` logons from `64.89.163.152` and `64.89.163.92` |
| 20:24:33–20:24:52 | Connections 22–24 enumerate `cr_corp_01.credentials` and query its columns |
| 20:24:53–20:24:54 | Tables in `cr_corp_01`, including `credentials`, are dropped |
| 20:26:40–20:26:41 | Tables in the `sakila` database are dropped |
| 20:26:56–20:26:58 | Tables in `world` are dropped; `DROP DATABASE` statements are executed |
| 20:26:58 | Ransom table created and extortion message inserted |
| 20:27:01 | Administrative privileges revoked from `root`@`'%'` |

---

## 🧾 Evidence & KQL Threat Hunting

### 1. Determine whether the credentials table was accessed before destruction

The investigation queried MySQL audit records for references to `credentials` during the incident window.

```kql
MySQLAudit_CL
| where TimeGenerated between (datetime(2026-09-08 12:00:00) .. datetime(2026-09-08 12:30:00))
| where RawData has "Query"
| extend RawData = replace_string(RawData, "\t", " ")
| extend Query = split(RawData, "Query")[1]
| where Query has "credentials"
| project TimeGenerated, Query, RawData
```

<img width="1475" height="400" alt="KQL evidence of credentials table access" src="https://github.com/user-attachments/assets/8e01f483-2b30-47af-b9ed-68adf56f3448" />

**Finding:** The audit evidence identified queries against the `credentials` table before the destructive activity. The table contained fields associated with customer identities and credentials.

The logs support the conclusion that the table was queried and its contents were targeted. They do not independently establish that the data was successfully transmitted off the host.

> **Validation note:** The query's `12:00–12:30` UTC-style timestamp window differs from the `20:24–20:27` log-local timeline. Confirm the workspace timezone and timestamp conversion before reusing the query or reporting exact times.

### 2. Reconstruct the destructive SQL sequence

This query filters for database and table deletion, database creation, ransom-related activity, and privilege revocation.

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

<img width="1567" height="546" alt="KQL evidence reconstructing destructive SQL activity" src="https://github.com/user-attachments/assets/0523bcca-2b30-48ab-96db-88ad2bac48e7" />

**Finding:** The query was used to reconstruct the destructive sequence, including database/table deletion, creation of the ransom-related artifact, and privilege revocation.

The sequence established that the incident involved more than failed authentication attempts: an authenticated database session performed destructive operations.

### 3. Review Windows endpoint telemetry

The investigation reviewed the following Microsoft Defender telemetry:

- `DeviceProcessEvents`
- `DeviceRegistryEvents`
- `DeviceFileEvents`
- `DeviceLogonEvents`

**Finding:** No host-level malware, web shells, or persistence mechanisms were detected in the reviewed process, registry, and file telemetry. The investigation also identified repeated failed RDP authentication attempts.

These results do not prove that the Windows host was never compromised; they establish that the reviewed telemetry did not confirm a successful host-level compromise.

---

## 💥 Impact Assessment

| Impact Area | Assessment | Details |
|---|---|---|
| Confidentiality | High risk | The `credentials` table was queried before database destruction. Off-host exfiltration remains unverified. |
| Integrity | Critical | Three databases were dropped, and associated tables and foreign-key constraints were removed. |
| Availability | Critical | Applications relying on `cr_corp_01` were affected by the database destruction. |
| Administrative recovery | High impact | Revocation of administrative DDL/DML privileges interfered with standard recovery workflows. |
| Regulatory exposure | Potential | Notification obligations may apply depending on the actual credential contents, applicable requirements, and confirmed data exposure. |

### Affected databases

- `cr_corp_01` — corporate/customer application database.
- `sakila` — MySQL sample schema.
- `world` — MySQL sample schema.

The `credentials` table contained fields identified in the investigation as `cred_id`, `customer_id`, `username`, `password`, `role`, and `last_login`.

The audit logs showed the queries and column references, but did not reveal the underlying credential values. Consequently, the investigation could not establish from those logs whether credentials were stored in cleartext or securely hashed.

---

## 🕵️ Threat Intelligence & Indicators of Compromise

The following indicators were extracted from the reviewed audit and authentication records.

| IOC Type | Value | Context |
|---|---|---|
| Bitcoin address | `bc1q0l7hr5v220f5qlqhjhg4p3jjqfkgudazzjnlkw` | Payment demand of 0.0108 BTC |
| Contact email | `ak+2mrn@onionmail.org` | Attacker contact information |
| Reference URL | `hxxps://spoo[.]me/mysql1` | Shortened link; unresolved and unvalidated |
| Campaign identifier | `2MRN` | Identifier in the ransom artifact |
| Ransom table | `RECOVER_YOUR_DATA.recover_your_data` | Created on September 8, 2026, at 20:26:58 |
| MySQL source IP | `64.89.163.152` | Failed `root` authentication attempts |
| MySQL source IP | `64.89.163.92` | Failed `root` authentication attempts |
| RDP source IP | `37.27.141.182` | 24 failed `administrator` logons |

*The indicators are evidence associated with this incident, not independently verified attribution. The reference URL has not been validated.*

---

## 🎯 MITRE ATT&CK Mapping

| Observed Behavior | ATT&CK Technique |
|---|---|
| Public scanning of ports `3306` and `3389` | `T1595.001` — Active Scanning: IP Blocks |
| Access to an exposed MySQL service | `T1190` — Exploit Public-Facing Application |
| RDP brute-force attempts | `T1110` — Brute Force |
| Remote access using a default or exposed account | `T1078.001` — Valid Accounts: Default Accounts |
| Database information collection | `T1213` — Data from Information Repositories |
| Privilege discovery | `T1069` — Permission Groups Discovery |
| Suspected automated collection | `T1119` — Automated Collection |
| Database/table destruction | `T1485` — Data Destruction |
| Ransom/extortion artifact | `T1491.001` — Internal Defacement |

---

## 🧠 Root Cause & Threat Analysis

### Primary attack vector

The primary exposure was the direct availability of MySQL on TCP port `3306` to the public internet, combined with weak or blank default credentials on the `root` account.

The authentication evidence showed repeated failed attempts followed by database query activity consistent with successful access. This pattern is consistent with opportunistic, automated scanning and credential guessing rather than a confirmed targeted intrusion.

### Authentication telemetry gap

The authentication event corresponding to the successful initial session, identified in the query logs as connections 22–24, was missing from the reviewed `MySqlAudit_CL-AuthLogs.csv` export.

The preceding failed attempts and subsequent query records supported the conclusion that the database was compromised, but the missing event limited reconstruction of the precise successful authentication.

### Concurrent RDP exposure

TCP port `3389` was also publicly exposed and received repeated failed RDP authentication attempts.

The investigation did not establish an operational connection between those RDP attempts and the MySQL destruction. Accordingly, the RDP activity should be treated as a separate observed attack surface unless additional evidence establishes a relationship.

---

## 🛡️ Mitigation & Response

### 1. Immediate containment

The incident response included:

- Restricting inbound TCP ports `3306` (MySQL) and `3389` (RDP) through the Azure Network Security Group and firewall.
- Limiting administrative access to VPN and Azure Bastion paths.
- Rotating and hardening MySQL `root` credentials, local Windows administrative credentials, and application connection strings.
- Capturing disk and memory forensic snapshots before host modifications or rebuilding.

### 2. Eradication and recovery

Following containment:

- The MySQL instance was re-provisioned from a clean, hardened base image.
- Extortion artifacts created by the attacker were excluded from the rebuilt environment.
- The `cr_corp_01` database was restored from the most recent verified pre-incident backup predating September 8 at 20:24.
- Schema and data integrity were validated before the database was returned to production.
- Local database users, database permissions, and operating-system accounts were audited for unauthorized access or permissions.

### 3. Recommended preventive controls

- Keep MySQL off the public internet wherever possible; use private networking, VPN, or tightly restricted administrative access.
- Disable remote `root` login and enforce strong, unique credentials.
- Apply least-privilege permissions to database accounts.
- Alert on successful MySQL authentication from unexpected public IP addresses.
- Detect destructive SQL statements such as `DROP DATABASE`, `DROP TABLE`, and mass deletion operations.
- Monitor suspicious ransom-related database names and extortion messages.
- Correlate failed authentication attempts with subsequent successful sessions and destructive queries.
- Retain complete authentication, query, and network telemetry to improve source attribution and exfiltration analysis.
- Test database backup restoration regularly and maintain protected, offline or immutable backups.

---

## 📚 What I Learned

This investigation reinforced the importance of correlating authentication records with database audit logs and endpoint telemetry to reconstruct an incident accurately.

The most significant finding was not simply that MySQL was exposed or that authentication attempts occurred. It was the sequence of database reconnaissance, credential-table access, database destruction, privilege revocation, and extortion within a short time window.

It also highlighted an important forensic limitation: **evidence of data access is not the same as evidence of successful data exfiltration.** Without adequate network-layer telemetry, the investigation could establish that the credentials table was queried but could not verify whether the data left the environment.

**Skills demonstrated:** MySQL audit log analysis • KQL threat hunting • Microsoft Defender for Endpoint telemetry review • Azure security • incident reconstruction • IOC extraction • MITRE ATT&CK mapping • impact assessment • incident response • database recovery

---

## 🏁 Final Assessment

The investigation confirmed that `FINANCE-SRV03` suffered a MySQL database compromise. The attacker remotely accessed the database, enumerated and queried the `cr_corp_01.credentials` table, dropped `cr_corp_01`, `sakila`, and `world`, revoked administrative privileges from the remote `root` account, and created an extortion artifact demanding 0.0108 BTC.

Concurrent RDP brute-force activity was confirmed, but the available evidence did not establish successful Windows host compromise or a direct connection between the RDP activity and the database attack. Off-host data exfiltration also remains unconfirmed because network-layer evidence was unavailable.

**Final scope:** Confirmed MySQL compromise involving sensitive-table access, data destruction, privilege revocation, and extortion. No confirmed Windows host-level compromise or off-host exfiltration.


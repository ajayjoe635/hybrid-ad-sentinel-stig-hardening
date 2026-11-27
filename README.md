# hybrid-ad-sentinel-stig-hardening
Hybrid Active Directory Hardening &amp; Cloud SIEM Threat Detection Lab



/////////////////////////////////////////////////////////////////////


# Hybrid Active Directory Hardening & Cloud SIEM Threat Detection Lab

**Repository:** `hybrid-ad-sentinel-stig-hardening`  
**Platform:** Windows Server 2025 (VMware Workstation) • Microsoft Sentinel • Kali Linux  
**Frameworks:** MITRE ATT&CK • CIS Benchmarks • DISA STIG • NIST SP 800-53

---

## Executive Overview
An end-to-end **Detect-to-Remediate** cybersecurity engineering lab built around a virtualized **Windows Server 2025 Active Directory Domain Controller (`corp.local`)** on VMware Workstation. This project simulates enterprise identity attack paths, builds custom KQL threat-hunting detections mapped to MITRE ATT&CK in **Microsoft Sentinel**, executes four phased **CIS / DISA STIG Group Policy (GPO)** hardening batches benchmarked with **HardeningKitty**, and validates protocol-level defenses from **Kali Linux**.

---

## Lab Architecture
* **Domain Controller (`DC01`):** Windows Server 2025 (`corp.local`, `192.168.10.10/24`) isolated on a VMware Host-Only virtual network
* **Cloud SIEM & Log Pipeline:** Microsoft Sentinel (`law-hybrid-siem-lab`), Azure Arc, Azure Monitor Agent (AMA), Data Collection Rules (DCR)
* **Compliance & Purple-Team Validation:** HardeningKitty (CIS / DISA STIG benchmarks) + Kali Linux (`192.168.10.20/24`) Nmap NSE & LDAP verification

---

## Phase 1: Active Directory Infrastructure & Granular Audit Telemetry
* Promoted Windows Server 2025 (`DC01`) to a root Domain Controller (`corp.local`) and structured tiered Organizational Units (`IT_Admins`, `Standard_Users`).
* Enforced `SCENoApplyLegacyAuditPolicy` and configured **26 Advanced Audit Policy subcategories** (`auditpol`), command-line process creation auditing (`Event ID 4688`), PowerShell Script Block/Module/Transcription logging (`Event ID 4104`), and a **196 MB** Security Event Log ceiling.
* Verified baseline authentication (`Event IDs 4624/4625`), account lockout (`Event ID 4740`), and privileged group change (`Event ID 4728`) telemetry.

---

## Phase 2: Cloud SIEM Threat Hunting & Custom KQL Detection Engineering
* Onboarded telemetry to a **Microsoft Sentinel** Log Analytics workspace (`law-hybrid-siem-lab`) to centralize Windows Security event monitoring (`SecurityEvent`).
* Authored Kusto Query Language (KQL) threat-hunting queries to isolate high-volume brute-force logon anomalies (**11,970+ failed Event ID `4625` attempts** targeting `SOC-FW-RDP` and domain endpoints).
* Engineered a **Scheduled Analytics Rule** (*Brute-Force Logon Spike on Domain Infrastructure*) mapped to **MITRE ATT&CK `T1110` (Brute Force)** with automated **Account**, **Host**, and **IP** entity mapping:
  ```kusto
  SecurityEvent
  | where EventID == 4625
  | summarize FailedAttempts = count() by Computer, TargetUserName, IpAddress, bin(TimeGenerated, 5m)
  | where FailedAttempts >= 10
  ```
* Triaged generated **High-severity** Sentinel incidents using visual entity investigation graphs prior to executing controlled cloud resource teardown.

---

## Phase 3: Phased CIS / DISA STIG Group Policy Hardening
Executed iterative, VM-snapshot-backed Group Policy (`GPO-AD-Security-Hardening` & `Default Domain Policy`) and PowerShell remediations benchmarked with **HardeningKitty**:

| Audit Stage | Hardening Focus | Compliance Score | Passed Controls | Key Remediations Applied |
| :--- | :--- | :---: | :---: | :--- |
| **Baseline** | Out-of-the-box Windows Server 2025 DC | **3.27** | **93 / 418** | Initial CIS/DISA STIG posture snapshot |
| **Batch 1** | Visibility & Audit Telemetry | **3.34** | **102 / 418** | 26 `auditpol` subcategories, CLI logging (`4688`), PowerShell logging (`4104`), 196 MB Security log |
| **Batch 2** | Credential Theft & Lateral Movement | **3.49** | **124 / 418** | LSASS PPL (`RunAsPPL`), Print Spooler disabled (PrintNightmare), LLMNR/NetBIOS/mDNS disabled, Remote SAM restricted |
| **Batch 3** | NTLM Auditing & Defender ASR Block | — | **143 / 418** | Domain-wide NTLM audit (`AuditNTLMInDomain=7`), 128-bit NTLM SSP, Defender MAPS/PUA & 13 ASR rules set to Block |
| **Batch 4** | RPC, SMB Audit, RDP/WinRM & Firewall | **3.94** | **174 / 418** | Custom SSP/AP block (`1857`), RPC auth/restrictions (`1692/1693`), SMB audit flags, RDP/WinRM hardening, Firewall policies |

* **Domain Password & Lockout Policy:** Enforced 14-character minimum password complexity and a 5-attempt account lockout threshold (15-minute lockout duration).

---

## Phase 4: Purple-Team Control Validation (Kali Linux -> `DC01`)
* **SMB Protocol & Signing Verification:** Executed `nmap -Pn -p 445 --script smb2-security-mode,smb-protocols 192.168.10.10`, confirming **SMBv1 is completely disabled** (only SMB `2.0.2`–`3.1.1` negotiated) and **SMB message signing is enabled and required** (`3.1.1`), neutralizing NTLM relay and SMB downgrade vectors.
* **LDAP Signing Enforcement:** Verified `ldapsearch` simple binds are rejected with `Strong(er) authentication required (8)`, proving mandatory LDAP integrity checking (`LDAPServerIntegrity = 2`).
* **Broadcast Name Resolution & Lockout Verification:** Confirmed zero broadcast name-resolution exposure (LLMNR/NBT-NS/mDNS disabled), verified automatic account lockout (`LockedOut = True`, `Event ID 4740`) after 5 invalid authentication attempts, and audited Active Directory DACLs and Kerberos SPN/AS-REP attributes.

---

## Phase 5: Documented Risk Acceptance Matrix
In accordance with enterprise NIST SP 800-53 / DISA STIG risk management practices, remaining non-applicable or hypervisor-constrained findings were formally documented rather than force-modified:

| HardeningKitty ID(s) | Control Name | Audit Status | Risk Acceptance Rationale |
| :--- | :--- | :--- | :--- |
| **`1708` (`High`)** | BitLocker Drive Encryption: Volume status | `FullyDecrypted` | Virtualized VMware guest operating without a vTPM or key recovery escrow infrastructure; encrypted at rest via host storage in production. |
| **`1614–1620`** | Device Guard: VBS / Credential Guard / HVCI | `Not available` | Nested hardware virtualization (VT-x/EPT) and Secure Boot are disabled on the VMware guest; documented as a hypervisor lab constraint. |
| **`1200`, `2300–2306`** | Restrict Network Logon / Block SMB & RPC Ports | `Excluded` | Intentionally excluded to preserve Active Directory domain authentication (`Authenticated Users`), LDAP, Kerberos, and GPO replication. |
| **`2400, 2403–2410`** | Xbox Services & GameSave Task | `Manual` / Inert | Consumer components bundled in default OS image; inactive on administrative Server 

SKUs. |

---

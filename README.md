# Hybrid Identity Security: Kerberos Exploitation & Remediation Analysis

<img width="1897" height="981" alt="Screenshot 2026-02-08 at 01 14 29" src="https://github.com/user-attachments/assets/3d7d28bb-fe07-4303-9b02-0fa08a7ea54d" />
<img width="1914" height="927" alt="Screenshot 2026-02-08 at 01 14 56" src="https://github.com/user-attachments/assets/399a2d90-8f6a-4ca1-972b-95007caa8deb" />
<img width="1916" height="843" alt="Screenshot 2026-02-08 at 01 15 35" src="https://github.com/user-attachments/assets/7ef22411-5e0e-40bf-8694-51a04e9f07a2" />
<img width="1917" height="1090" alt="Screenshot 2026-02-08 at 01 18 02" src="https://github.com/user-attachments/assets/66a98ab7-f659-46c3-8af4-7d9c4f1a1a5a" />
<img width="1912" height="1067" alt="Screenshot 2026-02-08 at 01 18 21" src="https://github.com/user-attachments/assets/99a0101c-7c24-400a-97ce-4980c661389c" />







## 🎯 Project Overview
This project simulates a **Kerberoasting** attack within a high-fidelity Windows Domain environment (`eagle.local`). The objective was to identify security debt in identity management—specifically the use of legacy encryption protocols and weak service account password policies—and demonstrate how these vulnerabilities lead to full domain compromise.

---

## 🛠️ Technical Stack
* **Reconnaissance:** PowerView (PowerSploit)
* **Exploitation:** Rubeus (GhostPack)
* **Cracking:** Hashcat (Mode 13100)
* **Environment:** Windows Server 2022, Parrot Security OS
* **Detection:** Splunk / KQL (Kusto Query Language)

---

## 🚀 Execution Phases

### 1. Identity Enumeration
I performed an audit of Service Principal Names (SPNs) to find accounts that map to services. Unlike standard user accounts, service accounts are high-value targets often exempted from frequent password rotations.
* **Tool:** `Get-DomainUser -SPN` (PowerView)
* **Finding:** Identified `svc-iam`, `webservice`, and `Administrator` as viable targets.

### 2. Ticket Extraction (The Attack)
Using **Rubeus**, I requested Kerberos Service Tickets (TGS) for the identified SPNs. 
* **Key Finding:** The environment defaulted to **RC4-HMAC (etype 23)** encryption.
* **Significance:** RC4 is cryptographically weak. Extracting these tickets allows for offline cracking without triggering account lockout policies on the Domain Controller.



### 3. Offline Password Recovery
I exfiltrated the TGS-REP hashes to a Linux-based cracking station to leverage GPU acceleration.
* **Command:** `hashcat -m 13100 -a 0 hashes.txt rockyou.txt`
* **Result:** Successfully recovered plaintext credentials for the `svc-iam` account, providing a foothold for lateral movement.

---

## 🛡️ Defensive Engineering & Mitigation

### Automated Detection (KQL)
To detect this activity in a production environment (Microsoft Sentinel/Azure Monitor), I developed the following query to alert on encryption downgrades:

```kusto
SecurityEvent
| where EventID == 4769 // Kerberos Service Ticket Requested
| where TicketEncryptionType == '0x17' // Detected Legacy RC4-HMAC
| where ServiceName !contains "$" // Filter out standard machine accounts
| summarize TicketCount = count() by TargetUserName, ServiceName, IpAddress
| where TicketCount > 5



